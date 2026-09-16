rule TTP_XOR_WriteProcessMemory_fdc5 {
  strings:
    $key_fdc5 = { aa b7 [2] 98 95 [2] 9e a0 [2] b0 a0 [2] 8f bc }

  condition:
    any of them
}