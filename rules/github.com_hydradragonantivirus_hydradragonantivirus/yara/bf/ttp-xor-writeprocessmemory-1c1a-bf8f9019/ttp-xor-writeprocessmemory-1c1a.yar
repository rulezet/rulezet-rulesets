rule TTP_XOR_WriteProcessMemory_1c1a {
  strings:
    $key_1c1a = { 4b 68 [2] 79 4a [2] 7f 7f [2] 51 7f [2] 6e 63 }

  condition:
    any of them
}