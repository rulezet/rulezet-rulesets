rule TTP_XOR_WriteProcessMemory_592c {
  strings:
    $key_592c = { 0e 5e [2] 3c 7c [2] 3a 49 [2] 14 49 [2] 2b 55 }

  condition:
    any of them
}