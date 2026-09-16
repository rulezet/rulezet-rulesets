rule TTP_XOR_WriteProcessMemory_fe5a {
  strings:
    $key_fe5a = { a9 28 [2] 9b 0a [2] 9d 3f [2] b3 3f [2] 8c 23 }

  condition:
    any of them
}