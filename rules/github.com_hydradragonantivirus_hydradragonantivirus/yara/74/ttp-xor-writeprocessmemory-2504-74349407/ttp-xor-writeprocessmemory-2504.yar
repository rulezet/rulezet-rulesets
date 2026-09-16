rule TTP_XOR_WriteProcessMemory_2504 {
  strings:
    $key_2504 = { 72 76 [2] 40 54 [2] 46 61 [2] 68 61 [2] 57 7d }

  condition:
    any of them
}