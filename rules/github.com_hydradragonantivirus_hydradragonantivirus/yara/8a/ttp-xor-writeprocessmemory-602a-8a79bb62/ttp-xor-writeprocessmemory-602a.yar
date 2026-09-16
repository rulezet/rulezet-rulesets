rule TTP_XOR_WriteProcessMemory_602a {
  strings:
    $key_602a = { 37 58 [2] 05 7a [2] 03 4f [2] 2d 4f [2] 12 53 }

  condition:
    any of them
}