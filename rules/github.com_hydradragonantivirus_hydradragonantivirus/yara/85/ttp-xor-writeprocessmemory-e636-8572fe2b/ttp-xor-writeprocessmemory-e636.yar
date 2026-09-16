rule TTP_XOR_WriteProcessMemory_e636 {
  strings:
    $key_e636 = { b1 44 [2] 83 66 [2] 85 53 [2] ab 53 [2] 94 4f }

  condition:
    any of them
}