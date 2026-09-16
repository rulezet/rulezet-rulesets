rule TTP_XOR_WriteProcessMemory_ff52 {
  strings:
    $key_ff52 = { a8 20 [2] 9a 02 [2] 9c 37 [2] b2 37 [2] 8d 2b }

  condition:
    any of them
}