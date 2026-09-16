rule TTP_XOR_WriteProcessMemory_2e08 {
  strings:
    $key_2e08 = { 79 7a [2] 4b 58 [2] 4d 6d [2] 63 6d [2] 5c 71 }

  condition:
    any of them
}