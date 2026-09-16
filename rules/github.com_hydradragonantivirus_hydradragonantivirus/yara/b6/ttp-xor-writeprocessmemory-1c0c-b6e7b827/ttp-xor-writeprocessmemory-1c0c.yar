rule TTP_XOR_WriteProcessMemory_1c0c {
  strings:
    $key_1c0c = { 4b 7e [2] 79 5c [2] 7f 69 [2] 51 69 [2] 6e 75 }

  condition:
    any of them
}