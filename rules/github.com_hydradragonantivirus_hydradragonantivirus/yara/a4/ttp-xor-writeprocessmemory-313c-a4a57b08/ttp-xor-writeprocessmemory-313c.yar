rule TTP_XOR_WriteProcessMemory_313c {
  strings:
    $key_313c = { 66 4e [2] 54 6c [2] 52 59 [2] 7c 59 [2] 43 45 }

  condition:
    any of them
}