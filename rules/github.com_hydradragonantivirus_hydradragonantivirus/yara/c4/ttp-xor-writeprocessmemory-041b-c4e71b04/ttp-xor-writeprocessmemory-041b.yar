rule TTP_XOR_WriteProcessMemory_041b {
  strings:
    $key_041b = { 53 69 [2] 61 4b [2] 67 7e [2] 49 7e [2] 76 62 }

  condition:
    any of them
}