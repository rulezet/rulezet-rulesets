rule TTP_XOR_WriteProcessMemory_fa32 {
  strings:
    $key_fa32 = { ad 40 [2] 9f 62 [2] 99 57 [2] b7 57 [2] 88 4b }

  condition:
    any of them
}