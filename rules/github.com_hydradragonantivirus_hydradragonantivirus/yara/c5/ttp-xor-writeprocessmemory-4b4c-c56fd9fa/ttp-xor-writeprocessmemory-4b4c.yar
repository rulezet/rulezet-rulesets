rule TTP_XOR_WriteProcessMemory_4b4c {
  strings:
    $key_4b4c = { 1c 3e [2] 2e 1c [2] 28 29 [2] 06 29 [2] 39 35 }

  condition:
    any of them
}