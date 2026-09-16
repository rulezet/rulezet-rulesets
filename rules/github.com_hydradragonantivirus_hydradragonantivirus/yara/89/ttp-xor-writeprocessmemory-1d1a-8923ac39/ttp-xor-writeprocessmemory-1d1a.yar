rule TTP_XOR_WriteProcessMemory_1d1a {
  strings:
    $key_1d1a = { 4a 68 [2] 78 4a [2] 7e 7f [2] 50 7f [2] 6f 63 }

  condition:
    any of them
}