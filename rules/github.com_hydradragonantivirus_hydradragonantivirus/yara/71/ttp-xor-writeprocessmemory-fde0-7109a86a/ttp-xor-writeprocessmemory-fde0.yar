rule TTP_XOR_WriteProcessMemory_fde0 {
  strings:
    $key_fde0 = { aa 92 [2] 98 b0 [2] 9e 85 [2] b0 85 [2] 8f 99 }

  condition:
    any of them
}