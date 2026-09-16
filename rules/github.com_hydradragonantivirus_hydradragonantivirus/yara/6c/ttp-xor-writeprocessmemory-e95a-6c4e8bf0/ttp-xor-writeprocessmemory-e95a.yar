rule TTP_XOR_WriteProcessMemory_e95a {
  strings:
    $key_e95a = { be 28 [2] 8c 0a [2] 8a 3f [2] a4 3f [2] 9b 23 }

  condition:
    any of them
}