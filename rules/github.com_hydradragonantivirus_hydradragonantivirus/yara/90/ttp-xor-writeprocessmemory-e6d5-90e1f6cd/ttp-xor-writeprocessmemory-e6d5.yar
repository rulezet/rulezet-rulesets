rule TTP_XOR_WriteProcessMemory_e6d5 {
  strings:
    $key_e6d5 = { b1 a7 [2] 83 85 [2] 85 b0 [2] ab b0 [2] 94 ac }

  condition:
    any of them
}