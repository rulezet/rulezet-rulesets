rule TTP_XOR_WriteProcessMemory_5aa0 {
  strings:
    $key_5aa0 = { 0d d2 [2] 3f f0 [2] 39 c5 [2] 17 c5 [2] 28 d9 }

  condition:
    any of them
}