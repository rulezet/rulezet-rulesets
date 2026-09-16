rule TTP_XOR_WriteProcessMemory_4b5c {
  strings:
    $key_4b5c = { 1c 2e [2] 2e 0c [2] 28 39 [2] 06 39 [2] 39 25 }

  condition:
    any of them
}