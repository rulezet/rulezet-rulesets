rule TTP_XOR_WriteProcessMemory_6cb0 {
  strings:
    $key_6cb0 = { 3b c2 [2] 09 e0 [2] 0f d5 [2] 21 d5 [2] 1e c9 }

  condition:
    any of them
}