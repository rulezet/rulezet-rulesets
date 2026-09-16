rule TTP_XOR_WriteProcessMemory_2533 {
  strings:
    $key_2533 = { 72 41 [2] 40 63 [2] 46 56 [2] 68 56 [2] 57 4a }

  condition:
    any of them
}