rule TTP_XOR_WriteProcessMemory_2e7a {
  strings:
    $key_2e7a = { 79 08 [2] 4b 2a [2] 4d 1f [2] 63 1f [2] 5c 03 }

  condition:
    any of them
}