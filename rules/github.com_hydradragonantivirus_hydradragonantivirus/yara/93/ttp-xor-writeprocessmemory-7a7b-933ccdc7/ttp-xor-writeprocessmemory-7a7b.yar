rule TTP_XOR_WriteProcessMemory_7a7b {
  strings:
    $key_7a7b = { 2d 09 [2] 1f 2b [2] 19 1e [2] 37 1e [2] 08 02 }

  condition:
    any of them
}