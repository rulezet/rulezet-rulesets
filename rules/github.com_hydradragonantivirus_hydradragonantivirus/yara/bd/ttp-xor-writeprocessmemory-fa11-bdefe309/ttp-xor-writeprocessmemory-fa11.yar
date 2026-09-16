rule TTP_XOR_WriteProcessMemory_fa11 {
  strings:
    $key_fa11 = { ad 63 [2] 9f 41 [2] 99 74 [2] b7 74 [2] 88 68 }

  condition:
    any of them
}