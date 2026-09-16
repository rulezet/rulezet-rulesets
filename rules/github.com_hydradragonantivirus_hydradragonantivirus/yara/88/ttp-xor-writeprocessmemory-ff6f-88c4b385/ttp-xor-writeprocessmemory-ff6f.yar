rule TTP_XOR_WriteProcessMemory_ff6f {
  strings:
    $key_ff6f = { a8 1d [2] 9a 3f [2] 9c 0a [2] b2 0a [2] 8d 16 }

  condition:
    any of them
}