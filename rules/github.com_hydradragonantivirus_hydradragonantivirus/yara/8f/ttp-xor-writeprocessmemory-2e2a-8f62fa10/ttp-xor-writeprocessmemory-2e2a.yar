rule TTP_XOR_WriteProcessMemory_2e2a {
  strings:
    $key_2e2a = { 79 58 [2] 4b 7a [2] 4d 4f [2] 63 4f [2] 5c 53 }

  condition:
    any of them
}