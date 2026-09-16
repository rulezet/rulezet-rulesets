rule TTP_XOR_WriteProcessMemory_1e1a {
  strings:
    $key_1e1a = { 49 68 [2] 7b 4a [2] 7d 7f [2] 53 7f [2] 6c 63 }

  condition:
    any of them
}