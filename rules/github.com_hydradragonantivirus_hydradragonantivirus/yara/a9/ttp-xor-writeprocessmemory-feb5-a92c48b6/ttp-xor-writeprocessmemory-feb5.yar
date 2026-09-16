rule TTP_XOR_WriteProcessMemory_feb5 {
  strings:
    $key_feb5 = { a9 c7 [2] 9b e5 [2] 9d d0 [2] b3 d0 [2] 8c cc }

  condition:
    any of them
}