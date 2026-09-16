rule TTP_XOR_WriteProcessMemory_ee56 {
  strings:
    $key_ee56 = { b9 24 [2] 8b 06 [2] 8d 33 [2] a3 33 [2] 9c 2f }

  condition:
    any of them
}