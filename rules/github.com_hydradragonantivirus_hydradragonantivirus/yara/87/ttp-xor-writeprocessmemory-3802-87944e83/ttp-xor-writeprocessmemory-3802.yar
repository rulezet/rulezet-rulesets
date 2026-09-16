rule TTP_XOR_WriteProcessMemory_3802 {
  strings:
    $key_3802 = { 6f 70 [2] 5d 52 [2] 5b 67 [2] 75 67 [2] 4a 7b }

  condition:
    any of them
}