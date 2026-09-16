rule TTP_XOR_WriteProcessMemory_1f2a {
  strings:
    $key_1f2a = { 48 58 [2] 7a 7a [2] 7c 4f [2] 52 4f [2] 6d 53 }

  condition:
    any of them
}