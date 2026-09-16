rule TTP_XOR_WriteProcessMemory_3577 {
  strings:
    $key_3577 = { 62 05 [2] 50 27 [2] 56 12 [2] 78 12 [2] 47 0e }

  condition:
    any of them
}