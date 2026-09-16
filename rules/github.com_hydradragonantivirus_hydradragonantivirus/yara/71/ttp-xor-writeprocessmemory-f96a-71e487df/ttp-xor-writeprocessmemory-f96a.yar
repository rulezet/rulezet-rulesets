rule TTP_XOR_WriteProcessMemory_f96a {
  strings:
    $key_f96a = { ae 18 [2] 9c 3a [2] 9a 0f [2] b4 0f [2] 8b 13 }

  condition:
    any of them
}