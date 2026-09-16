rule TTP_XOR_WriteProcessMemory_391c {
  strings:
    $key_391c = { 6e 6e [2] 5c 4c [2] 5a 79 [2] 74 79 [2] 4b 65 }

  condition:
    any of them
}