rule TTP_XOR_WriteProcessMemory_fdd5 {
  strings:
    $key_fdd5 = { aa a7 [2] 98 85 [2] 9e b0 [2] b0 b0 [2] 8f ac }

  condition:
    any of them
}