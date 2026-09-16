rule TTP_XOR_WriteProcessMemory_04b4 {
  strings:
    $key_04b4 = { 53 c6 [2] 61 e4 [2] 67 d1 [2] 49 d1 [2] 76 cd }

  condition:
    any of them
}