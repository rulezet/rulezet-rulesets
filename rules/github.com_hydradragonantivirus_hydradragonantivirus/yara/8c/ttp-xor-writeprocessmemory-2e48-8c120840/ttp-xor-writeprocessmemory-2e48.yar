rule TTP_XOR_WriteProcessMemory_2e48 {
  strings:
    $key_2e48 = { 79 3a [2] 4b 18 [2] 4d 2d [2] 63 2d [2] 5c 31 }

  condition:
    any of them
}