rule TTP_XOR_WriteProcessMemory_0d6a {
  strings:
    $key_0d6a = { 5a 18 [2] 68 3a [2] 6e 0f [2] 40 0f [2] 7f 13 }

  condition:
    any of them
}