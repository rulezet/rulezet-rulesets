rule TTP_XOR_WriteProcessMemory_7a1b {
  strings:
    $key_7a1b = { 2d 69 [2] 1f 4b [2] 19 7e [2] 37 7e [2] 08 62 }

  condition:
    any of them
}