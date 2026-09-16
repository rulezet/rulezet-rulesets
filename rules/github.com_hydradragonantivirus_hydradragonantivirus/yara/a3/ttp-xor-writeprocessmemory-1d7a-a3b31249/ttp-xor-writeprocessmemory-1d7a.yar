rule TTP_XOR_WriteProcessMemory_1d7a {
  strings:
    $key_1d7a = { 4a 08 [2] 78 2a [2] 7e 1f [2] 50 1f [2] 6f 03 }

  condition:
    any of them
}