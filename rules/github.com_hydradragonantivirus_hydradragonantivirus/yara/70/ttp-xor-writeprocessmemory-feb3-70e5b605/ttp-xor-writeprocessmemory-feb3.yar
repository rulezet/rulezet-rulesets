rule TTP_XOR_WriteProcessMemory_feb3 {
  strings:
    $key_feb3 = { a9 c1 [2] 9b e3 [2] 9d d6 [2] b3 d6 [2] 8c ca }

  condition:
    any of them
}