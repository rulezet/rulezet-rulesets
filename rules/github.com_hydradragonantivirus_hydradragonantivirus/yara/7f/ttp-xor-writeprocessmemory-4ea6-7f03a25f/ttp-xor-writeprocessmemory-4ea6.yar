rule TTP_XOR_WriteProcessMemory_4ea6 {
  strings:
    $key_4ea6 = { 19 d4 [2] 2b f6 [2] 2d c3 [2] 03 c3 [2] 3c df }

  condition:
    any of them
}