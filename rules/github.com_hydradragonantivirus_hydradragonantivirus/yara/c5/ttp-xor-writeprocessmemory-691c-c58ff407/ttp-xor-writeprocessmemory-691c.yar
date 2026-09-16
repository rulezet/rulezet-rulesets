rule TTP_XOR_WriteProcessMemory_691c {
  strings:
    $key_691c = { 3e 6e [2] 0c 4c [2] 0a 79 [2] 24 79 [2] 1b 65 }

  condition:
    any of them
}