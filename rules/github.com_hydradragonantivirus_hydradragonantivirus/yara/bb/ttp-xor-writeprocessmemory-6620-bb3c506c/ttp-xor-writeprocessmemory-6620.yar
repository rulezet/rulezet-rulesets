rule TTP_XOR_WriteProcessMemory_6620 {
  strings:
    $key_6620 = { 31 52 [2] 03 70 [2] 05 45 [2] 2b 45 [2] 14 59 }

  condition:
    any of them
}