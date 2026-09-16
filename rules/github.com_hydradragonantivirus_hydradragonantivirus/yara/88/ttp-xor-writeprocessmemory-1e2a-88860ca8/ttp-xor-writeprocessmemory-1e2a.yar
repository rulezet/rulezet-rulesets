rule TTP_XOR_WriteProcessMemory_1e2a {
  strings:
    $key_1e2a = { 49 58 [2] 7b 7a [2] 7d 4f [2] 53 4f [2] 6c 53 }

  condition:
    any of them
}