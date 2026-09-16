rule TTP_XOR_WriteProcessMemory_592a {
  strings:
    $key_592a = { 0e 58 [2] 3c 7a [2] 3a 4f [2] 14 4f [2] 2b 53 }

  condition:
    any of them
}