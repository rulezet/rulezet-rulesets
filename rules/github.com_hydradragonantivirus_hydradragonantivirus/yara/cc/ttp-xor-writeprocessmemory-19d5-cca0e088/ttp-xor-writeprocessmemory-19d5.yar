rule TTP_XOR_WriteProcessMemory_19d5 {
  strings:
    $key_19d5 = { 4e a7 [2] 7c 85 [2] 7a b0 [2] 54 b0 [2] 6b ac }

  condition:
    any of them
}