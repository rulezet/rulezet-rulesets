rule TTP_XOR_WriteProcessMemory_c8c3 {
  strings:
    $key_c8c3 = { 9f b1 [2] ad 93 [2] ab a6 [2] 85 a6 [2] ba ba }

  condition:
    any of them
}