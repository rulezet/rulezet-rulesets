rule TTP_XOR_WriteProcessMemory_ff0a {
  strings:
    $key_ff0a = { a8 78 [2] 9a 5a [2] 9c 6f [2] b2 6f [2] 8d 73 }

  condition:
    any of them
}