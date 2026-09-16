rule TTP_XOR_WriteProcessMemory_3b1a {
  strings:
    $key_3b1a = { 6c 68 [2] 5e 4a [2] 58 7f [2] 76 7f [2] 49 63 }

  condition:
    any of them
}