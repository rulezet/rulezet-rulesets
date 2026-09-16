rule TTP_XOR_WriteProcessMemory_2e1c {
  strings:
    $key_2e1c = { 79 6e [2] 4b 4c [2] 4d 79 [2] 63 79 [2] 5c 65 }

  condition:
    any of them
}