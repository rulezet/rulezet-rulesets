rule TTP_XOR_WriteProcessMemory_e437 {
  strings:
    $key_e437 = { b3 45 [2] 81 67 [2] 87 52 [2] a9 52 [2] 96 4e }

  condition:
    any of them
}