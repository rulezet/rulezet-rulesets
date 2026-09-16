rule TTP_XOR_WriteProcessMemory_390f {
  strings:
    $key_390f = { 6e 7d [2] 5c 5f [2] 5a 6a [2] 74 6a [2] 4b 76 }

  condition:
    any of them
}