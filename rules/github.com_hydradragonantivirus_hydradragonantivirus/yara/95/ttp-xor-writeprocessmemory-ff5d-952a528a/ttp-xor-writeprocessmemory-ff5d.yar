rule TTP_XOR_WriteProcessMemory_ff5d {
  strings:
    $key_ff5d = { a8 2f [2] 9a 0d [2] 9c 38 [2] b2 38 [2] 8d 24 }

  condition:
    any of them
}