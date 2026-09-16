rule TTP_XOR_WriteProcessMemory_eeb5 {
  strings:
    $key_eeb5 = { b9 c7 [2] 8b e5 [2] 8d d0 [2] a3 d0 [2] 9c cc }

  condition:
    any of them
}