rule TTP_XOR_WriteProcessMemory_ca0e {
  strings:
    $key_ca0e = { 9d 7c [2] af 5e [2] a9 6b [2] 87 6b [2] b8 77 }

  condition:
    any of them
}