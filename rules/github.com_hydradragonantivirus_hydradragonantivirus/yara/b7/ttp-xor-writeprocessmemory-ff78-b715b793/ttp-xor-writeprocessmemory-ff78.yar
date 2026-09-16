rule TTP_XOR_WriteProcessMemory_ff78 {
  strings:
    $key_ff78 = { a8 0a [2] 9a 28 [2] 9c 1d [2] b2 1d [2] 8d 01 }

  condition:
    any of them
}