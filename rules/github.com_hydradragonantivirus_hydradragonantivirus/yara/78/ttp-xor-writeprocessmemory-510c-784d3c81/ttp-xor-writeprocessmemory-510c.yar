rule TTP_XOR_WriteProcessMemory_510c {
  strings:
    $key_510c = { 06 7e [2] 34 5c [2] 32 69 [2] 1c 69 [2] 23 75 }

  condition:
    any of them
}