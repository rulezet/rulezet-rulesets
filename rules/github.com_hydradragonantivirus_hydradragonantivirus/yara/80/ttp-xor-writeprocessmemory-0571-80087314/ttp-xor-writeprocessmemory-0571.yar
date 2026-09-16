rule TTP_XOR_WriteProcessMemory_0571 {
  strings:
    $key_0571 = { 52 03 [2] 60 21 [2] 66 14 [2] 48 14 [2] 77 08 }

  condition:
    any of them
}