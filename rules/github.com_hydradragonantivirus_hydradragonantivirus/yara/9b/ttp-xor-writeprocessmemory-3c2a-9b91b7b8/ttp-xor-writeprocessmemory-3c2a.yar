rule TTP_XOR_WriteProcessMemory_3c2a {
  strings:
    $key_3c2a = { 6b 58 [2] 59 7a [2] 5f 4f [2] 71 4f [2] 4e 53 }

  condition:
    any of them
}