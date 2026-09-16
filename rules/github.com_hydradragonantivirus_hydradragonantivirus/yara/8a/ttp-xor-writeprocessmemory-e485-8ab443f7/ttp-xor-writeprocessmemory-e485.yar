rule TTP_XOR_WriteProcessMemory_e485 {
  strings:
    $key_e485 = { b3 f7 [2] 81 d5 [2] 87 e0 [2] a9 e0 [2] 96 fc }

  condition:
    any of them
}