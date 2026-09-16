rule TTP_XOR_WriteProcessMemory_19d1 {
  strings:
    $key_19d1 = { 4e a3 [2] 7c 81 [2] 7a b4 [2] 54 b4 [2] 6b a8 }

  condition:
    any of them
}