rule TTP_XOR_WriteProcessMemory_fa76 {
  strings:
    $key_fa76 = { ad 04 [2] 9f 26 [2] 99 13 [2] b7 13 [2] 88 0f }

  condition:
    any of them
}