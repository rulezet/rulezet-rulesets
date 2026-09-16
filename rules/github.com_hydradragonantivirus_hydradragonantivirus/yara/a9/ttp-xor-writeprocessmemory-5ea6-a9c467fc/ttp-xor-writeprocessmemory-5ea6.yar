rule TTP_XOR_WriteProcessMemory_5ea6 {
  strings:
    $key_5ea6 = { 09 d4 [2] 3b f6 [2] 3d c3 [2] 13 c3 [2] 2c df }

  condition:
    any of them
}