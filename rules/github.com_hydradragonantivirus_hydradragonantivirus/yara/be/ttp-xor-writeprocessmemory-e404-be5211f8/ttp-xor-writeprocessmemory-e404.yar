rule TTP_XOR_WriteProcessMemory_e404 {
  strings:
    $key_e404 = { b3 76 [2] 81 54 [2] 87 61 [2] a9 61 [2] 96 7d }

  condition:
    any of them
}