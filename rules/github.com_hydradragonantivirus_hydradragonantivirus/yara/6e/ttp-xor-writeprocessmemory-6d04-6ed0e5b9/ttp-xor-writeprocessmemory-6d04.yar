rule TTP_XOR_WriteProcessMemory_6d04 {
  strings:
    $key_6d04 = { 3a 76 [2] 08 54 [2] 0e 61 [2] 20 61 [2] 1f 7d }

  condition:
    any of them
}