rule TTP_XOR_WriteProcessMemory_4a4c {
  strings:
    $key_4a4c = { 1d 3e [2] 2f 1c [2] 29 29 [2] 07 29 [2] 38 35 }

  condition:
    any of them
}