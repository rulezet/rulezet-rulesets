rule TTP_XOR_WriteProcessMemory_cab2 {
  strings:
    $key_cab2 = { 9d c0 [2] af e2 [2] a9 d7 [2] 87 d7 [2] b8 cb }

  condition:
    any of them
}