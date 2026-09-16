rule TTP_XOR_WriteProcessMemory_e434 {
  strings:
    $key_e434 = { b3 46 [2] 81 64 [2] 87 51 [2] a9 51 [2] 96 4d }

  condition:
    any of them
}