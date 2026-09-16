rule TTP_XOR_WriteProcessMemory_61c4 {
  strings:
    $key_61c4 = { 36 b6 [2] 04 94 [2] 02 a1 [2] 2c a1 [2] 13 bd }

  condition:
    any of them
}