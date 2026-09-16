rule TTP_XOR_WriteProcessMemory_e91c {
  strings:
    $key_e91c = { be 6e [2] 8c 4c [2] 8a 79 [2] a4 79 [2] 9b 65 }

  condition:
    any of them
}