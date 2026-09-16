rule TTP_XOR_WriteProcessMemory_43c5 {
  strings:
    $key_43c5 = { 14 b7 [2] 26 95 [2] 20 a0 [2] 0e a0 [2] 31 bc }

  condition:
    any of them
}