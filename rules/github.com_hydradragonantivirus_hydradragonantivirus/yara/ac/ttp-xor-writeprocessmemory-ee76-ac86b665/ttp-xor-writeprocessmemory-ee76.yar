rule TTP_XOR_WriteProcessMemory_ee76 {
  strings:
    $key_ee76 = { b9 04 [2] 8b 26 [2] 8d 13 [2] a3 13 [2] 9c 0f }

  condition:
    any of them
}