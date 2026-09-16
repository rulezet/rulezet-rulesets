rule TTP_XOR_WriteProcessMemory_2e0c {
  strings:
    $key_2e0c = { 79 7e [2] 4b 5c [2] 4d 69 [2] 63 69 [2] 5c 75 }

  condition:
    any of them
}