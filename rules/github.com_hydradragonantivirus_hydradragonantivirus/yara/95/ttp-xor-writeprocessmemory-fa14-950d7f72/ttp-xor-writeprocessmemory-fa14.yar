rule TTP_XOR_WriteProcessMemory_fa14 {
  strings:
    $key_fa14 = { ad 66 [2] 9f 44 [2] 99 71 [2] b7 71 [2] 88 6d }

  condition:
    any of them
}