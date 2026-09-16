rule TTP_XOR_WriteProcessMemory_173a {
  strings:
    $key_173a = { 40 48 [2] 72 6a [2] 74 5f [2] 5a 5f [2] 65 43 }

  condition:
    any of them
}