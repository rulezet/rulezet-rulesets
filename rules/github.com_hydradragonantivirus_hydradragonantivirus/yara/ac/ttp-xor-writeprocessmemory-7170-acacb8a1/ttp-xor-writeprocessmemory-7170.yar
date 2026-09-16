rule TTP_XOR_WriteProcessMemory_7170 {
  strings:
    $key_7170 = { 26 02 [2] 14 20 [2] 12 15 [2] 3c 15 [2] 03 09 }

  condition:
    any of them
}