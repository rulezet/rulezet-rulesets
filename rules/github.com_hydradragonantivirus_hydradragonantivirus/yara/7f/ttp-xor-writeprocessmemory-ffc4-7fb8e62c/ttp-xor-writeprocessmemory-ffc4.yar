rule TTP_XOR_WriteProcessMemory_ffc4 {
  strings:
    $key_ffc4 = { a8 b6 [2] 9a 94 [2] 9c a1 [2] b2 a1 [2] 8d bd }

  condition:
    any of them
}