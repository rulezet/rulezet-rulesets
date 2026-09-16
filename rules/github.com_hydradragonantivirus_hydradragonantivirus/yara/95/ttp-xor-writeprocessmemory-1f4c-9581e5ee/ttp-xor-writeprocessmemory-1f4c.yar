rule TTP_XOR_WriteProcessMemory_1f4c {
  strings:
    $key_1f4c = { 48 3e [2] 7a 1c [2] 7c 29 [2] 52 29 [2] 6d 35 }

  condition:
    any of them
}