rule TTP_XOR_WriteProcessMemory_171b {
  strings:
    $key_171b = { 40 69 [2] 72 4b [2] 74 7e [2] 5a 7e [2] 65 62 }

  condition:
    any of them
}