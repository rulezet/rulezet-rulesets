rule TTP_XOR_WriteProcessMemory_2e5d {
  strings:
    $key_2e5d = { 79 2f [2] 4b 0d [2] 4d 38 [2] 63 38 [2] 5c 24 }

  condition:
    any of them
}