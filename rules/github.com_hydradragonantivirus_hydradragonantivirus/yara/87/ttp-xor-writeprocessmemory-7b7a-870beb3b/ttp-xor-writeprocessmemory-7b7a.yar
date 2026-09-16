rule TTP_XOR_WriteProcessMemory_7b7a {
  strings:
    $key_7b7a = { 2c 08 [2] 1e 2a [2] 18 1f [2] 36 1f [2] 09 03 }

  condition:
    any of them
}