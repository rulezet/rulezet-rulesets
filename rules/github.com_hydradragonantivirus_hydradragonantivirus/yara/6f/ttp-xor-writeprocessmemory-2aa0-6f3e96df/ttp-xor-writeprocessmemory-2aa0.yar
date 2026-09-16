rule TTP_XOR_WriteProcessMemory_2aa0 {
  strings:
    $key_2aa0 = { 7d d2 [2] 4f f0 [2] 49 c5 [2] 67 c5 [2] 58 d9 }

  condition:
    any of them
}