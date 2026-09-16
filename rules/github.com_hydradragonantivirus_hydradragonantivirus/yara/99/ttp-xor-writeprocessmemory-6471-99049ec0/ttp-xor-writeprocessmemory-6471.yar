rule TTP_XOR_WriteProcessMemory_6471 {
  strings:
    $key_6471 = { 33 03 [2] 01 21 [2] 07 14 [2] 29 14 [2] 16 08 }

  condition:
    any of them
}