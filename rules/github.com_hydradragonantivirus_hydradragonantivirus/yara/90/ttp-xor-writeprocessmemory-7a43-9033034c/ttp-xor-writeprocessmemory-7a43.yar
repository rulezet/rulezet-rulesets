rule TTP_XOR_WriteProcessMemory_7a43 {
  strings:
    $key_7a43 = { 2d 31 [2] 1f 13 [2] 19 26 [2] 37 26 [2] 08 3a }

  condition:
    any of them
}