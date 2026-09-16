rule TTP_XOR_WriteProcessMemory_e620 {
  strings:
    $key_e620 = { b1 52 [2] 83 70 [2] 85 45 [2] ab 45 [2] 94 59 }

  condition:
    any of them
}