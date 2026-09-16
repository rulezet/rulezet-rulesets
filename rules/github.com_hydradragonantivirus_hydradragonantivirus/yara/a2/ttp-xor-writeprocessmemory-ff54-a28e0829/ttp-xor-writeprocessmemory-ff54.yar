rule TTP_XOR_WriteProcessMemory_ff54 {
  strings:
    $key_ff54 = { a8 26 [2] 9a 04 [2] 9c 31 [2] b2 31 [2] 8d 2d }

  condition:
    any of them
}