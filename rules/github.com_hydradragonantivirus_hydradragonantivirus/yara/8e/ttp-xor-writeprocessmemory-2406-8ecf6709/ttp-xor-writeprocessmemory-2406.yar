rule TTP_XOR_WriteProcessMemory_2406 {
  strings:
    $key_2406 = { 73 74 [2] 41 56 [2] 47 63 [2] 69 63 [2] 56 7f }

  condition:
    any of them
}