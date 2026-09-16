rule TTP_XOR_WriteProcessMemory_370a {
  strings:
    $key_370a = { 60 78 [2] 52 5a [2] 54 6f [2] 7a 6f [2] 45 73 }

  condition:
    any of them
}