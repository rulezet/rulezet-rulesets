rule TTP_XOR_WriteProcessMemory_dc0b {
  strings:
    $key_dc0b = { 8b 79 [2] b9 5b [2] bf 6e [2] 91 6e [2] ae 72 }

  condition:
    any of them
}