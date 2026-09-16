rule TTP_XOR_WriteProcessMemory_ee82 {
  strings:
    $key_ee82 = { b9 f0 [2] 8b d2 [2] 8d e7 [2] a3 e7 [2] 9c fb }

  condition:
    any of them
}