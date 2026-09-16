rule TTP_XOR_WriteProcessMemory_3926 {
  strings:
    $key_3926 = { 6e 54 [2] 5c 76 [2] 5a 43 [2] 74 43 [2] 4b 5f }

  condition:
    any of them
}