rule TTP_XOR_WriteProcessMemory_ff23 {
  strings:
    $key_ff23 = { a8 51 [2] 9a 73 [2] 9c 46 [2] b2 46 [2] 8d 5a }

  condition:
    any of them
}