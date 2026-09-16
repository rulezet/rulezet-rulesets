rule TTP_XOR_WriteProcessMemory_412c {
  strings:
    $key_412c = { 16 5e [2] 24 7c [2] 22 49 [2] 0c 49 [2] 33 55 }

  condition:
    any of them
}