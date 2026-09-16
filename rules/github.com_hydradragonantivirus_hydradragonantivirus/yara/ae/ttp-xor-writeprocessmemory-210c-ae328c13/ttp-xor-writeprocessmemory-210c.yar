rule TTP_XOR_WriteProcessMemory_210c {
  strings:
    $key_210c = { 76 7e [2] 44 5c [2] 42 69 [2] 6c 69 [2] 53 75 }

  condition:
    any of them
}