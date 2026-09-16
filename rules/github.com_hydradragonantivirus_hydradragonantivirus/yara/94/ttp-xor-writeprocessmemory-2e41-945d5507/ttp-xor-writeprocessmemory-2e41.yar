rule TTP_XOR_WriteProcessMemory_2e41 {
  strings:
    $key_2e41 = { 79 33 [2] 4b 11 [2] 4d 24 [2] 63 24 [2] 5c 38 }

  condition:
    any of them
}