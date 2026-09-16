rule TTP_XOR_WriteProcessMemory_ff04 {
  strings:
    $key_ff04 = { a8 76 [2] 9a 54 [2] 9c 61 [2] b2 61 [2] 8d 7d }

  condition:
    any of them
}