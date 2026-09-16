rule TTP_XOR_WriteProcessMemory_5073 {
  strings:
    $key_5073 = { 07 01 [2] 35 23 [2] 33 16 [2] 1d 16 [2] 22 0a }

  condition:
    any of them
}