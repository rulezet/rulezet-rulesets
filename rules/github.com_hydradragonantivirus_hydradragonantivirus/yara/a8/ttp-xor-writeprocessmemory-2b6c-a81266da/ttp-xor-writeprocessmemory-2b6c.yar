rule TTP_XOR_WriteProcessMemory_2b6c {
  strings:
    $key_2b6c = { 7c 1e [2] 4e 3c [2] 48 09 [2] 66 09 [2] 59 15 }

  condition:
    any of them
}