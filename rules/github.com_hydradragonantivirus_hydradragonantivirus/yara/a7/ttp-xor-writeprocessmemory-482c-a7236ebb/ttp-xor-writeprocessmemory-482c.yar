rule TTP_XOR_WriteProcessMemory_482c {
  strings:
    $key_482c = { 1f 5e [2] 2d 7c [2] 2b 49 [2] 05 49 [2] 3a 55 }

  condition:
    any of them
}