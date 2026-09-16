rule TTP_XOR_WriteProcessMemory_422c {
  strings:
    $key_422c = { 15 5e [2] 27 7c [2] 21 49 [2] 0f 49 [2] 30 55 }

  condition:
    any of them
}