rule TTP_XOR_WriteProcessMemory_0eb2 {
  strings:
    $key_0eb2 = { 59 c0 [2] 6b e2 [2] 6d d7 [2] 43 d7 [2] 7c cb }

  condition:
    any of them
}