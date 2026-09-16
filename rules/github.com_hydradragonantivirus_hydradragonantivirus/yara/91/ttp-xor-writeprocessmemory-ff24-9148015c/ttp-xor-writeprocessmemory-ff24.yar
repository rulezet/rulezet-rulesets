rule TTP_XOR_WriteProcessMemory_ff24 {
  strings:
    $key_ff24 = { a8 56 [2] 9a 74 [2] 9c 41 [2] b2 41 [2] 8d 5d }

  condition:
    any of them
}