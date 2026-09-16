rule TTP_XOR_WriteProcessMemory_2cd0 {
  strings:
    $key_2cd0 = { 7b a2 [2] 49 80 [2] 4f b5 [2] 61 b5 [2] 5e a9 }

  condition:
    any of them
}