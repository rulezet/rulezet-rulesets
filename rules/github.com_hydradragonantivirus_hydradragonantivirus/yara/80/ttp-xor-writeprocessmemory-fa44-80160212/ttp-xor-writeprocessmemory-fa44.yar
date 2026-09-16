rule TTP_XOR_WriteProcessMemory_fa44 {
  strings:
    $key_fa44 = { ad 36 [2] 9f 14 [2] 99 21 [2] b7 21 [2] 88 3d }

  condition:
    any of them
}