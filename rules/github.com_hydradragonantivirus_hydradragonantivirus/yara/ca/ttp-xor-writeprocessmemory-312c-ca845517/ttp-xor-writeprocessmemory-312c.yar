rule TTP_XOR_WriteProcessMemory_312c {
  strings:
    $key_312c = { 66 5e [2] 54 7c [2] 52 49 [2] 7c 49 [2] 43 55 }

  condition:
    any of them
}