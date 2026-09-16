rule TTP_XOR_WriteProcessMemory_2e30 {
  strings:
    $key_2e30 = { 79 42 [2] 4b 60 [2] 4d 55 [2] 63 55 [2] 5c 49 }

  condition:
    any of them
}