rule TTP_XOR_WriteProcessMemory_ff1d {
  strings:
    $key_ff1d = { a8 6f [2] 9a 4d [2] 9c 78 [2] b2 78 [2] 8d 64 }

  condition:
    any of them
}