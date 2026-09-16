rule TTP_XOR_WriteProcessMemory_6420 {
  strings:
    $key_6420 = { 33 52 [2] 01 70 [2] 07 45 [2] 29 45 [2] 16 59 }

  condition:
    any of them
}