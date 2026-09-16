rule TTP_XOR_WriteProcessMemory_786a {
  strings:
    $key_786a = { 2f 18 [2] 1d 3a [2] 1b 0f [2] 35 0f [2] 0a 13 }

  condition:
    any of them
}