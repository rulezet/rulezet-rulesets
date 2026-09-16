rule TTP_XOR_WriteProcessMemory_267c {
  strings:
    $key_267c = { 71 0e [2] 43 2c [2] 45 19 [2] 6b 19 [2] 54 05 }

  condition:
    any of them
}