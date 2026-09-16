rule TTP_XOR_WriteProcessMemory_e424 {
  strings:
    $key_e424 = { b3 56 [2] 81 74 [2] 87 41 [2] a9 41 [2] 96 5d }

  condition:
    any of them
}