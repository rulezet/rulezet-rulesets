rule TTP_XOR_WriteProcessMemory_ca6e {
  strings:
    $key_ca6e = { 9d 1c [2] af 3e [2] a9 0b [2] 87 0b [2] b8 17 }

  condition:
    any of them
}