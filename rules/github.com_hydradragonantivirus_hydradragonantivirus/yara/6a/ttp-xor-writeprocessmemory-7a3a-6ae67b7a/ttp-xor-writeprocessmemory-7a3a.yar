rule TTP_XOR_WriteProcessMemory_7a3a {
  strings:
    $key_7a3a = { 2d 48 [2] 1f 6a [2] 19 5f [2] 37 5f [2] 08 43 }

  condition:
    any of them
}