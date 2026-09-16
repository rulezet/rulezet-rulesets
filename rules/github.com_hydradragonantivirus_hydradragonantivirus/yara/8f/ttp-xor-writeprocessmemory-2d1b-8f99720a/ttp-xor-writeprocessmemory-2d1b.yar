rule TTP_XOR_WriteProcessMemory_2d1b {
  strings:
    $key_2d1b = { 7a 69 [2] 48 4b [2] 4e 7e [2] 60 7e [2] 5f 62 }

  condition:
    any of them
}