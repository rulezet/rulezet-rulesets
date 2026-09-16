rule TTP_XOR_WriteProcessMemory_565c {
  strings:
    $key_565c = { 01 2e [2] 33 0c [2] 35 39 [2] 1b 39 [2] 24 25 }

  condition:
    any of them
}