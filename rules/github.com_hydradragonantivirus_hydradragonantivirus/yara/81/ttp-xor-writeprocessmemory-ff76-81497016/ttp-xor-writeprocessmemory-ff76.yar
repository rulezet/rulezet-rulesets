rule TTP_XOR_WriteProcessMemory_ff76 {
  strings:
    $key_ff76 = { a8 04 [2] 9a 26 [2] 9c 13 [2] b2 13 [2] 8d 0f }

  condition:
    any of them
}