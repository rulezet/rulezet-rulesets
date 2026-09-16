rule TTP_XOR_WriteProcessMemory_eeb2 {
  strings:
    $key_eeb2 = { b9 c0 [2] 8b e2 [2] 8d d7 [2] a3 d7 [2] 9c cb }

  condition:
    any of them
}