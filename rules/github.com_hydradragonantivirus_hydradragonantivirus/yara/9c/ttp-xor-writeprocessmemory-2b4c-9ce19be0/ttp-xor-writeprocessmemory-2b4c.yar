rule TTP_XOR_WriteProcessMemory_2b4c {
  strings:
    $key_2b4c = { 7c 3e [2] 4e 1c [2] 48 29 [2] 66 29 [2] 59 35 }

  condition:
    any of them
}