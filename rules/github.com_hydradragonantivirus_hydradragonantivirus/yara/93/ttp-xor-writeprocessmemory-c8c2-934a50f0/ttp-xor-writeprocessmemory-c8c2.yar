rule TTP_XOR_WriteProcessMemory_c8c2 {
  strings:
    $key_c8c2 = { 9f b0 [2] ad 92 [2] ab a7 [2] 85 a7 [2] ba bb }

  condition:
    any of them
}