rule TTP_XOR_WriteProcessMemory_4433 {
  strings:
    $key_4433 = { 13 41 [2] 21 63 [2] 27 56 [2] 09 56 [2] 36 4a }

  condition:
    any of them
}