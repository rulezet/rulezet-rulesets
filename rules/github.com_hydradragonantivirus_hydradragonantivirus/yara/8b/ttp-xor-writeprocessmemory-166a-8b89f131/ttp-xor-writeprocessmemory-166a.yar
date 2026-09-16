rule TTP_XOR_WriteProcessMemory_166a {
  strings:
    $key_166a = { 41 18 [2] 73 3a [2] 75 0f [2] 5b 0f [2] 64 13 }

  condition:
    any of them
}