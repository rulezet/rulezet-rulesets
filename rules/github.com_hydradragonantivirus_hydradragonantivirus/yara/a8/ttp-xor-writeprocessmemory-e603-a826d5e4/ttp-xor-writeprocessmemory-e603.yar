rule TTP_XOR_WriteProcessMemory_e603 {
  strings:
    $key_e603 = { b1 71 [2] 83 53 [2] 85 66 [2] ab 66 [2] 94 7a }

  condition:
    any of them
}