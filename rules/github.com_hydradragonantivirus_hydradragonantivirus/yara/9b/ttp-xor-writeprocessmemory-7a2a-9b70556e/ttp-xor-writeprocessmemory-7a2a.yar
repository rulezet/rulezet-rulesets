rule TTP_XOR_WriteProcessMemory_7a2a {
  strings:
    $key_7a2a = { 2d 58 [2] 1f 7a [2] 19 4f [2] 37 4f [2] 08 53 }

  condition:
    any of them
}