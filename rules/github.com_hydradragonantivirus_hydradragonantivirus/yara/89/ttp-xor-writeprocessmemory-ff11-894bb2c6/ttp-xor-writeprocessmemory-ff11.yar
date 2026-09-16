rule TTP_XOR_WriteProcessMemory_ff11 {
  strings:
    $key_ff11 = { a8 63 [2] 9a 41 [2] 9c 74 [2] b2 74 [2] 8d 68 }

  condition:
    any of them
}