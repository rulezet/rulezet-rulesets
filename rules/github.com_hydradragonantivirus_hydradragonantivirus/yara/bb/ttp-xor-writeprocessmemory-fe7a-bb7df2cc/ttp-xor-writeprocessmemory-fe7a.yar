rule TTP_XOR_WriteProcessMemory_fe7a {
  strings:
    $key_fe7a = { a9 08 [2] 9b 2a [2] 9d 1f [2] b3 1f [2] 8c 03 }

  condition:
    any of them
}