rule TTP_XOR_WriteProcessMemory_2936 {
  strings:
    $key_2936 = { 7e 44 [2] 4c 66 [2] 4a 53 [2] 64 53 [2] 5b 4f }

  condition:
    any of them
}