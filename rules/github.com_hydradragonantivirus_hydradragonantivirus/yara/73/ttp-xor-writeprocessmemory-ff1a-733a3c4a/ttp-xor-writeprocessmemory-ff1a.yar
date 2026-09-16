rule TTP_XOR_WriteProcessMemory_ff1a {
  strings:
    $key_ff1a = { a8 68 [2] 9a 4a [2] 9c 7f [2] b2 7f [2] 8d 63 }

  condition:
    any of them
}