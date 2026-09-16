rule TTP_XOR_WriteProcessMemory_f846 {
  strings:
    $key_f846 = { af 34 [2] 9d 16 [2] 9b 23 [2] b5 23 [2] 8a 3f }

  condition:
    any of them
}