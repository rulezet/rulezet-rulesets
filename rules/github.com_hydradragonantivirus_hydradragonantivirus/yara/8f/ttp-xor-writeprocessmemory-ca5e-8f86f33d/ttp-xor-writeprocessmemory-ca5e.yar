rule TTP_XOR_WriteProcessMemory_ca5e {
  strings:
    $key_ca5e = { 9d 2c [2] af 0e [2] a9 3b [2] 87 3b [2] b8 27 }

  condition:
    any of them
}