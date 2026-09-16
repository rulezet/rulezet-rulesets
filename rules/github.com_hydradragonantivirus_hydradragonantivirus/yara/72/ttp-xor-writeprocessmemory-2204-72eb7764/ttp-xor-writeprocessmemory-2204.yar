rule TTP_XOR_WriteProcessMemory_2204 {
  strings:
    $key_2204 = { 75 76 [2] 47 54 [2] 41 61 [2] 6f 61 [2] 50 7d }

  condition:
    any of them
}