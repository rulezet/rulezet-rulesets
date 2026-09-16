rule TTP_XOR_WriteProcessMemory_7c3c {
  strings:
    $key_7c3c = { 2b 4e [2] 19 6c [2] 1f 59 [2] 31 59 [2] 0e 45 }

  condition:
    any of them
}