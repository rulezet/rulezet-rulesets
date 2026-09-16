rule TTP_XOR_WriteProcessMemory_3f2a {
  strings:
    $key_3f2a = { 68 58 [2] 5a 7a [2] 5c 4f [2] 72 4f [2] 4d 53 }

  condition:
    any of them
}