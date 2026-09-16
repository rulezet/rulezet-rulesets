rule TTP_XOR_WriteProcessMemory_2d04 {
  strings:
    $key_2d04 = { 7a 76 [2] 48 54 [2] 4e 61 [2] 60 61 [2] 5f 7d }

  condition:
    any of them
}