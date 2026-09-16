rule TTP_XOR_WriteProcessMemory_221a {
  strings:
    $key_221a = { 75 68 [2] 47 4a [2] 41 7f [2] 6f 7f [2] 50 63 }

  condition:
    any of them
}