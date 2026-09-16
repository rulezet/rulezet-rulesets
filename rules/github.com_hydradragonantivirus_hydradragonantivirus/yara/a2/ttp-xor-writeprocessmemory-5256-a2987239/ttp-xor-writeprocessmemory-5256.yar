rule TTP_XOR_WriteProcessMemory_5256 {
  strings:
    $key_5256 = { 05 24 [2] 37 06 [2] 31 33 [2] 1f 33 [2] 20 2f }

  condition:
    any of them
}