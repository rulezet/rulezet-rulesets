rule TTP_XOR_WriteProcessMemory_ff1f {
  strings:
    $key_ff1f = { a8 6d [2] 9a 4f [2] 9c 7a [2] b2 7a [2] 8d 66 }

  condition:
    any of them
}