rule TTP_XOR_WriteProcessMemory_0d1b {
  strings:
    $key_0d1b = { 5a 69 [2] 68 4b [2] 6e 7e [2] 40 7e [2] 7f 62 }

  condition:
    any of them
}