rule TTP_XOR_WriteProcessMemory_2366 {
  strings:
    $key_2366 = { 74 14 [2] 46 36 [2] 40 03 [2] 6e 03 [2] 51 1f }

  condition:
    any of them
}