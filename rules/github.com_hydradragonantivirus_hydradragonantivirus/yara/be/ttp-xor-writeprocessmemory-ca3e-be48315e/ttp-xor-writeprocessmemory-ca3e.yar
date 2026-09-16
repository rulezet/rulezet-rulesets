rule TTP_XOR_WriteProcessMemory_ca3e {
  strings:
    $key_ca3e = { 9d 4c [2] af 6e [2] a9 5b [2] 87 5b [2] b8 47 }

  condition:
    any of them
}