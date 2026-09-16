rule TTP_XOR_WriteProcessMemory_f8f6 {
  strings:
    $key_f8f6 = { af 84 [2] 9d a6 [2] 9b 93 [2] b5 93 [2] 8a 8f }

  condition:
    any of them
}