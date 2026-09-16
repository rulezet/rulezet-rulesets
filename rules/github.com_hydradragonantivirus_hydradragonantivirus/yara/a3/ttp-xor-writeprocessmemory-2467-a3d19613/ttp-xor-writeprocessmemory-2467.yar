rule TTP_XOR_WriteProcessMemory_2467 {
  strings:
    $key_2467 = { 73 15 [2] 41 37 [2] 47 02 [2] 69 02 [2] 56 1e }

  condition:
    any of them
}