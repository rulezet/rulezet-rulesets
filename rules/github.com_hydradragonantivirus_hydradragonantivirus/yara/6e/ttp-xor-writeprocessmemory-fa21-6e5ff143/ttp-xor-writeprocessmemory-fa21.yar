rule TTP_XOR_WriteProcessMemory_fa21 {
  strings:
    $key_fa21 = { ad 53 [2] 9f 71 [2] 99 44 [2] b7 44 [2] 88 58 }

  condition:
    any of them
}