rule TTP_XOR_WriteProcessMemory_7e21 {
  strings:
    $key_7e21 = { 29 53 [2] 1b 71 [2] 1d 44 [2] 33 44 [2] 0c 58 }

  condition:
    any of them
}