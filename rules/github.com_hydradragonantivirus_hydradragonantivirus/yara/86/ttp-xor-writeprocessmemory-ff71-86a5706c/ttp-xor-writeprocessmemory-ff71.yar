rule TTP_XOR_WriteProcessMemory_ff71 {
  strings:
    $key_ff71 = { a8 03 [2] 9a 21 [2] 9c 14 [2] b2 14 [2] 8d 08 }

  condition:
    any of them
}