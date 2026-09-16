rule TTP_XOR_WriteProcessMemory_ff14 {
  strings:
    $key_ff14 = { a8 66 [2] 9a 44 [2] 9c 71 [2] b2 71 [2] 8d 6d }

  condition:
    any of them
}