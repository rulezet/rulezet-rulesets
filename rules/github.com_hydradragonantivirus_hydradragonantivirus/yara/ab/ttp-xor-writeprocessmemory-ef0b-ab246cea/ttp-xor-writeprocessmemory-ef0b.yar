rule TTP_XOR_WriteProcessMemory_ef0b {
  strings:
    $key_ef0b = { b8 79 [2] 8a 5b [2] 8c 6e [2] a2 6e [2] 9d 72 }

  condition:
    any of them
}