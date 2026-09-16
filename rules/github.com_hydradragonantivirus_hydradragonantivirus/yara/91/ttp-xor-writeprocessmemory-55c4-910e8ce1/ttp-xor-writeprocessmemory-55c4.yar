rule TTP_XOR_WriteProcessMemory_55c4 {
  strings:
    $key_55c4 = { 02 b6 [2] 30 94 [2] 36 a1 [2] 18 a1 [2] 27 bd }

  condition:
    any of them
}