rule TTP_XOR_WriteProcessMemory_2f0c {
  strings:
    $key_2f0c = { 78 7e [2] 4a 5c [2] 4c 69 [2] 62 69 [2] 5d 75 }

  condition:
    any of them
}