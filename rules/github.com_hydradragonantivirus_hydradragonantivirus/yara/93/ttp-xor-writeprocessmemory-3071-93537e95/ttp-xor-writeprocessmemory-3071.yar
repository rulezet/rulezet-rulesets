rule TTP_XOR_WriteProcessMemory_3071 {
  strings:
    $key_3071 = { 67 03 [2] 55 21 [2] 53 14 [2] 7d 14 [2] 42 08 }

  condition:
    any of them
}