rule TTP_XOR_WriteProcessMemory_6b0c {
  strings:
    $key_6b0c = { 3c 7e [2] 0e 5c [2] 08 69 [2] 26 69 [2] 19 75 }

  condition:
    any of them
}