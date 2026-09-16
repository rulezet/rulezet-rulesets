rule TTP_XOR_WriteProcessMemory_2cb0 {
  strings:
    $key_2cb0 = { 7b c2 [2] 49 e0 [2] 4f d5 [2] 61 d5 [2] 5e c9 }

  condition:
    any of them
}