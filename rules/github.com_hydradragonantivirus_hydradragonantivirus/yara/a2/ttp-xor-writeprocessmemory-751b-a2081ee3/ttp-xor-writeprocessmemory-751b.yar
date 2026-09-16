rule TTP_XOR_WriteProcessMemory_751b {
  strings:
    $key_751b = { 22 69 [2] 10 4b [2] 16 7e [2] 38 7e [2] 07 62 }

  condition:
    any of them
}