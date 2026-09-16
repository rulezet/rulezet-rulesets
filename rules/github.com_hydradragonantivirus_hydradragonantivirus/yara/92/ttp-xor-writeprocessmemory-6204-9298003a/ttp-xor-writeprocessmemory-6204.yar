rule TTP_XOR_WriteProcessMemory_6204 {
  strings:
    $key_6204 = { 35 76 [2] 07 54 [2] 01 61 [2] 2f 61 [2] 10 7d }

  condition:
    any of them
}