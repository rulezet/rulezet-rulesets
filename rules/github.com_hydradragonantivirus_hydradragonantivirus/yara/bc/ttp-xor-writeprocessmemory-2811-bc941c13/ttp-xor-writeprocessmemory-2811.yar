rule TTP_XOR_WriteProcessMemory_2811 {
  strings:
    $key_2811 = { 7f 63 [2] 4d 41 [2] 4b 74 [2] 65 74 [2] 5a 68 }

  condition:
    any of them
}