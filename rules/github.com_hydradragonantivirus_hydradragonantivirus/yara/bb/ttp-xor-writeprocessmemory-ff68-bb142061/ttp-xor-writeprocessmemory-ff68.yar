rule TTP_XOR_WriteProcessMemory_ff68 {
  strings:
    $key_ff68 = { a8 1a [2] 9a 38 [2] 9c 0d [2] b2 0d [2] 8d 11 }

  condition:
    any of them
}