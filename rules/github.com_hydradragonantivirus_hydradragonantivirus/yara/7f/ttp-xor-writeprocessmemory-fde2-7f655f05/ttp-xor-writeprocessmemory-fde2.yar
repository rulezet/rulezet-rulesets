rule TTP_XOR_WriteProcessMemory_fde2 {
  strings:
    $key_fde2 = { aa 90 [2] 98 b2 [2] 9e 87 [2] b0 87 [2] 8f 9b }

  condition:
    any of them
}