rule TTP_XOR_WriteProcessMemory_7a4b {
  strings:
    $key_7a4b = { 2d 39 [2] 1f 1b [2] 19 2e [2] 37 2e [2] 08 32 }

  condition:
    any of them
}