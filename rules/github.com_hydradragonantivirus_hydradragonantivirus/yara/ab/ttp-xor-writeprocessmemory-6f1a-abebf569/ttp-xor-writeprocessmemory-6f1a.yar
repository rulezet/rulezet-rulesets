rule TTP_XOR_WriteProcessMemory_6f1a {
  strings:
    $key_6f1a = { 38 68 [2] 0a 4a [2] 0c 7f [2] 22 7f [2] 1d 63 }

  condition:
    any of them
}