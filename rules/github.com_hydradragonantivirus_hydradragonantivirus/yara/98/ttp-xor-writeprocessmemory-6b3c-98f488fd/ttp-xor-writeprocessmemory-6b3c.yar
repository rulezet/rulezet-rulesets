rule TTP_XOR_WriteProcessMemory_6b3c {
  strings:
    $key_6b3c = { 3c 4e [2] 0e 6c [2] 08 59 [2] 26 59 [2] 19 45 }

  condition:
    any of them
}