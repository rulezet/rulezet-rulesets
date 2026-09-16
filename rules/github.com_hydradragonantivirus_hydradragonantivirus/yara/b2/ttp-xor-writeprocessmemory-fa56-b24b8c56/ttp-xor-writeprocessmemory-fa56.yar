rule TTP_XOR_WriteProcessMemory_fa56 {
  strings:
    $key_fa56 = { ad 24 [2] 9f 06 [2] 99 33 [2] b7 33 [2] 88 2f }

  condition:
    any of them
}