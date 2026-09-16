rule TTP_XOR_WriteProcessMemory_32d5 {
  strings:
    $key_32d5 = { 65 a7 [2] 57 85 [2] 51 b0 [2] 7f b0 [2] 40 ac }

  condition:
    any of them
}