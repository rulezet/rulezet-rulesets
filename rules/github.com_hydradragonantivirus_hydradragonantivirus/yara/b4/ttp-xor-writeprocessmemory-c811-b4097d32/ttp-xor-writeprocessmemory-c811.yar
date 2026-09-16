rule TTP_XOR_WriteProcessMemory_c811 {
  strings:
    $key_c811 = { 9f 63 [2] ad 41 [2] ab 74 [2] 85 74 [2] ba 68 }

  condition:
    any of them
}