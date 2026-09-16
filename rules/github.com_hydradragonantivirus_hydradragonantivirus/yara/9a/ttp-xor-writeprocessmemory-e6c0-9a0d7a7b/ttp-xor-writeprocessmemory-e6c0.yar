rule TTP_XOR_WriteProcessMemory_e6c0 {
  strings:
    $key_e6c0 = { b1 b2 [2] 83 90 [2] 85 a5 [2] ab a5 [2] 94 b9 }

  condition:
    any of them
}