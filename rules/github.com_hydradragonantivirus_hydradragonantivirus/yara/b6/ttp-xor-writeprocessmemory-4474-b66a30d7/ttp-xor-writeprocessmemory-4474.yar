rule TTP_XOR_WriteProcessMemory_4474 {
  strings:
    $key_4474 = { 13 06 [2] 21 24 [2] 27 11 [2] 09 11 [2] 36 0d }

  condition:
    any of them
}