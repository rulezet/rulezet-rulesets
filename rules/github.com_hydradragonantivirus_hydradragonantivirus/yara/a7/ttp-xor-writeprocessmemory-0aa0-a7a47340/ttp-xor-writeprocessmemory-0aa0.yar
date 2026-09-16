rule TTP_XOR_WriteProcessMemory_0aa0 {
  strings:
    $key_0aa0 = { 5d d2 [2] 6f f0 [2] 69 c5 [2] 47 c5 [2] 78 d9 }

  condition:
    any of them
}