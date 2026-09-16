rule TTP_XOR_WriteProcessMemory_182a {
  strings:
    $key_182a = { 4f 58 [2] 7d 7a [2] 7b 4f [2] 55 4f [2] 6a 53 }

  condition:
    any of them
}