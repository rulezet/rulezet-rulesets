rule TTP_XOR_WriteProcessMemory_f95a {
  strings:
    $key_f95a = { ae 28 [2] 9c 0a [2] 9a 3f [2] b4 3f [2] 8b 23 }

  condition:
    any of them
}