rule TTP_XOR_WriteProcessMemory_231b {
  strings:
    $key_231b = { 74 69 [2] 46 4b [2] 40 7e [2] 6e 7e [2] 51 62 }

  condition:
    any of them
}