rule TTP_XOR_WriteProcessMemory_5094 {
  strings:
    $key_5094 = { 07 e6 [2] 35 c4 [2] 33 f1 [2] 1d f1 [2] 22 ed }

  condition:
    any of them
}