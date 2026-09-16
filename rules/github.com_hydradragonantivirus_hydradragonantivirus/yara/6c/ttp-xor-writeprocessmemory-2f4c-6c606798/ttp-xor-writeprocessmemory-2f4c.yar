rule TTP_XOR_WriteProcessMemory_2f4c {
  strings:
    $key_2f4c = { 78 3e [2] 4a 1c [2] 4c 29 [2] 62 29 [2] 5d 35 }

  condition:
    any of them
}