rule TTP_XOR_WriteProcessMemory_2dc6 {
  strings:
    $key_2dc6 = { 7a b4 [2] 48 96 [2] 4e a3 [2] 60 a3 [2] 5f bf }

  condition:
    any of them
}