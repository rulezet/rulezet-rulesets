rule TTP_XOR_WriteProcessMemory_ca5b {
  strings:
    $key_ca5b = { 9d 29 [2] af 0b [2] a9 3e [2] 87 3e [2] b8 22 }

  condition:
    any of them
}