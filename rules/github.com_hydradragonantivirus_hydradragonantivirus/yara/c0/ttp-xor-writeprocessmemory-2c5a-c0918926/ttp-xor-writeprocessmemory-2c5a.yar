rule TTP_XOR_WriteProcessMemory_2c5a {
  strings:
    $key_2c5a = { 7b 28 [2] 49 0a [2] 4f 3f [2] 61 3f [2] 5e 23 }

  condition:
    any of them
}