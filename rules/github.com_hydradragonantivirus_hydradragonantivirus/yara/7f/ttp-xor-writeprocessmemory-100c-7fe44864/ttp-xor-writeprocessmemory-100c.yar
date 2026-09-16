rule TTP_XOR_WriteProcessMemory_100c {
  strings:
    $key_100c = { 47 7e [2] 75 5c [2] 73 69 [2] 5d 69 [2] 62 75 }

  condition:
    any of them
}