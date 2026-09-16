rule TTP_XOR_WriteProcessMemory_234b {
  strings:
    $key_234b = { 74 39 [2] 46 1b [2] 40 2e [2] 6e 2e [2] 51 32 }

  condition:
    any of them
}