rule TTP_XOR_WriteProcessMemory_eec5 {
  strings:
    $key_eec5 = { b9 b7 [2] 8b 95 [2] 8d a0 [2] a3 a0 [2] 9c bc }

  condition:
    any of them
}