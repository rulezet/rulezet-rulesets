rule TTP_XOR_WriteProcessMemory_2c4a {
  strings:
    $key_2c4a = { 7b 38 [2] 49 1a [2] 4f 2f [2] 61 2f [2] 5e 33 }

  condition:
    any of them
}