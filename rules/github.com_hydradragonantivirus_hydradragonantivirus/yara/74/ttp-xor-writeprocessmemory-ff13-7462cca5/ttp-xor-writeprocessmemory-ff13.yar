rule TTP_XOR_WriteProcessMemory_ff13 {
  strings:
    $key_ff13 = { a8 61 [2] 9a 43 [2] 9c 76 [2] b2 76 [2] 8d 6a }

  condition:
    any of them
}