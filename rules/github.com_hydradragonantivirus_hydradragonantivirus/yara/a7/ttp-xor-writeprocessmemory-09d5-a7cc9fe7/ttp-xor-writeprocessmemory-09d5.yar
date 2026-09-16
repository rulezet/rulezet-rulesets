rule TTP_XOR_WriteProcessMemory_09d5 {
  strings:
    $key_09d5 = { 5e a7 [2] 6c 85 [2] 6a b0 [2] 44 b0 [2] 7b ac }

  condition:
    any of them
}