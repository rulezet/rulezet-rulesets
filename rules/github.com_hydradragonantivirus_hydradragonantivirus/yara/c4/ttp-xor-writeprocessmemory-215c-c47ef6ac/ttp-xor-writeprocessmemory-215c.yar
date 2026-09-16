rule TTP_XOR_WriteProcessMemory_215c {
  strings:
    $key_215c = { 76 2e [2] 44 0c [2] 42 39 [2] 6c 39 [2] 53 25 }

  condition:
    any of them
}