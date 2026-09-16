rule TTP_XOR_WriteProcessMemory_4c4c {
  strings:
    $key_4c4c = { 1b 3e [2] 29 1c [2] 2f 29 [2] 01 29 [2] 3e 35 }

  condition:
    any of them
}