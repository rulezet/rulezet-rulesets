rule TTP_XOR_WriteProcessMemory_ffc1 {
  strings:
    $key_ffc1 = { a8 b3 [2] 9a 91 [2] 9c a4 [2] b2 a4 [2] 8d b8 }

  condition:
    any of them
}