rule TTP_XOR_WriteProcessMemory_191a {
  strings:
    $key_191a = { 4e 68 [2] 7c 4a [2] 7a 7f [2] 54 7f [2] 6b 63 }

  condition:
    any of them
}