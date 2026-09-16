rule TTP_XOR_WriteProcessMemory_222a {
  strings:
    $key_222a = { 75 58 [2] 47 7a [2] 41 4f [2] 6f 4f [2] 50 53 }

  condition:
    any of them
}