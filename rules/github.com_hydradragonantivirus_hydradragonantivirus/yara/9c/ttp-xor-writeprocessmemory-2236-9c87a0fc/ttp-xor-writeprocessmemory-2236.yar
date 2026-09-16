rule TTP_XOR_WriteProcessMemory_2236 {
  strings:
    $key_2236 = { 75 44 [2] 47 66 [2] 41 53 [2] 6f 53 [2] 50 4f }

  condition:
    any of them
}