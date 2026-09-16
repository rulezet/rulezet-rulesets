rule TTP_XOR_WriteProcessMemory_6402 {
  strings:
    $key_6402 = { 33 70 [2] 01 52 [2] 07 67 [2] 29 67 [2] 16 7b }

  condition:
    any of them
}