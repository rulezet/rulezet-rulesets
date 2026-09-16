rule TTP_XOR_WriteProcessMemory_fe2f {
  strings:
    $key_fe2f = { a9 5d [2] 9b 7f [2] 9d 4a [2] b3 4a [2] 8c 56 }

  condition:
    any of them
}