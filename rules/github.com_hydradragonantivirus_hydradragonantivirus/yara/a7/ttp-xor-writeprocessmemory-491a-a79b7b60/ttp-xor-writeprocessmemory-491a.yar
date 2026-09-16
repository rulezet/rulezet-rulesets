rule TTP_XOR_WriteProcessMemory_491a {
  strings:
    $key_491a = { 1e 68 [2] 2c 4a [2] 2a 7f [2] 04 7f [2] 3b 63 }

  condition:
    any of them
}