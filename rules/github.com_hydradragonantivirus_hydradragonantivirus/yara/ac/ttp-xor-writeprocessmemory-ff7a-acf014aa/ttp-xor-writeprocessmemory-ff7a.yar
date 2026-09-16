rule TTP_XOR_WriteProcessMemory_ff7a {
  strings:
    $key_ff7a = { a8 08 [2] 9a 2a [2] 9c 1f [2] b2 1f [2] 8d 03 }

  condition:
    any of them
}