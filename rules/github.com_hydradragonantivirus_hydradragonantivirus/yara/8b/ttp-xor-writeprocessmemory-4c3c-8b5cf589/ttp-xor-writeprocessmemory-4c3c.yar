rule TTP_XOR_WriteProcessMemory_4c3c {
  strings:
    $key_4c3c = { 1b 4e [2] 29 6c [2] 2f 59 [2] 01 59 [2] 3e 45 }

  condition:
    any of them
}