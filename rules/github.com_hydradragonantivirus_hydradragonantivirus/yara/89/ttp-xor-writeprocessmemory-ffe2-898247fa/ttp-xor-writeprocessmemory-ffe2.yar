rule TTP_XOR_WriteProcessMemory_ffe2 {
  strings:
    $key_ffe2 = { a8 90 [2] 9a b2 [2] 9c 87 [2] b2 87 [2] 8d 9b }

  condition:
    any of them
}