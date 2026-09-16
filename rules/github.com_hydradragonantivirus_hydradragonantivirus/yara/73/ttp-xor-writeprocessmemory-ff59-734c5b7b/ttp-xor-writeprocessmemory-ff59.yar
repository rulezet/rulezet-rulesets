rule TTP_XOR_WriteProcessMemory_ff59 {
  strings:
    $key_ff59 = { a8 2b [2] 9a 09 [2] 9c 3c [2] b2 3c [2] 8d 20 }

  condition:
    any of them
}