rule TTP_XOR_WriteProcessMemory_19d0 {
  strings:
    $key_19d0 = { 4e a2 [2] 7c 80 [2] 7a b5 [2] 54 b5 [2] 6b a9 }

  condition:
    any of them
}