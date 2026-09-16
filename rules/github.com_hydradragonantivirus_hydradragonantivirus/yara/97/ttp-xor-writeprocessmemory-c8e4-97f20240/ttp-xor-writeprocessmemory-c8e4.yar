rule TTP_XOR_WriteProcessMemory_c8e4 {
  strings:
    $key_c8e4 = { 9f 96 [2] ad b4 [2] ab 81 [2] 85 81 [2] ba 9d }

  condition:
    any of them
}