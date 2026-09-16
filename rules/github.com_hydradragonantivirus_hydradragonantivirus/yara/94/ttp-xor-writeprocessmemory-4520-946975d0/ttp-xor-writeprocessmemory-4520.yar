rule TTP_XOR_WriteProcessMemory_4520 {
  strings:
    $key_4520 = { 12 52 [2] 20 70 [2] 26 45 [2] 08 45 [2] 37 59 }

  condition:
    any of them
}