rule TTP_XOR_WriteProcessMemory_2b0c {
  strings:
    $key_2b0c = { 7c 7e [2] 4e 5c [2] 48 69 [2] 66 69 [2] 59 75 }

  condition:
    any of them
}