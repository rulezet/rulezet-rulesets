rule TTP_XOR_WriteProcessMemory_e90c {
  strings:
    $key_e90c = { be 7e [2] 8c 5c [2] 8a 69 [2] a4 69 [2] 9b 75 }

  condition:
    any of them
}