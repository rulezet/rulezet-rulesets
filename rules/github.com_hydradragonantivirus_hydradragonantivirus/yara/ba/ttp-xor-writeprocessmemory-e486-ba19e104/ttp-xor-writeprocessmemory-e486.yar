rule TTP_XOR_WriteProcessMemory_e486 {
  strings:
    $key_e486 = { b3 f4 [2] 81 d6 [2] 87 e3 [2] a9 e3 [2] 96 ff }

  condition:
    any of them
}