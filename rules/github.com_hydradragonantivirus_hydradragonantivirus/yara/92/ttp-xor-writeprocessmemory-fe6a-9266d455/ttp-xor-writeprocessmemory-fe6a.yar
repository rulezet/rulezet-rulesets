rule TTP_XOR_WriteProcessMemory_fe6a {
  strings:
    $key_fe6a = { a9 18 [2] 9b 3a [2] 9d 0f [2] b3 0f [2] 8c 13 }

  condition:
    any of them
}