rule TTP_XOR_WriteProcessMemory_601b {
  strings:
    $key_601b = { 37 69 [2] 05 4b [2] 03 7e [2] 2d 7e [2] 12 62 }

  condition:
    any of them
}