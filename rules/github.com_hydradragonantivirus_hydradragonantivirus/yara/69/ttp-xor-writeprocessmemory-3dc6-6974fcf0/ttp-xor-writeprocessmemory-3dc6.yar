rule TTP_XOR_WriteProcessMemory_3dc6 {
  strings:
    $key_3dc6 = { 6a b4 [2] 58 96 [2] 5e a3 [2] 70 a3 [2] 4f bf }

  condition:
    any of them
}