rule TTP_XOR_WriteProcessMemory_faa0 {
  strings:
    $key_faa0 = { ad d2 [2] 9f f0 [2] 99 c5 [2] b7 c5 [2] 88 d9 }

  condition:
    any of them
}