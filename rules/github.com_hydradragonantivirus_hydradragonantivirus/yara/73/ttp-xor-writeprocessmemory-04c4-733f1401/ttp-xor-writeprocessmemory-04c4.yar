rule TTP_XOR_WriteProcessMemory_04c4 {
  strings:
    $key_04c4 = { 53 b6 [2] 61 94 [2] 67 a1 [2] 49 a1 [2] 76 bd }

  condition:
    any of them
}