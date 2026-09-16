rule TTP_XOR_WriteProcessMemory_3dc3 {
  strings:
    $key_3dc3 = { 6a b1 [2] 58 93 [2] 5e a6 [2] 70 a6 [2] 4f ba }

  condition:
    any of them
}