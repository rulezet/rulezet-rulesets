rule TTP_XOR_WriteProcessMemory_e6c4 {
  strings:
    $key_e6c4 = { b1 b6 [2] 83 94 [2] 85 a1 [2] ab a1 [2] 94 bd }

  condition:
    any of them
}