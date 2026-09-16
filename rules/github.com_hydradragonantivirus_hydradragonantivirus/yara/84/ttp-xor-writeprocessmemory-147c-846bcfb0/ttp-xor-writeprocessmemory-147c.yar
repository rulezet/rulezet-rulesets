rule TTP_XOR_WriteProcessMemory_147c {
  strings:
    $key_147c = { 43 0e [2] 71 2c [2] 77 19 [2] 59 19 [2] 66 05 }

  condition:
    any of them
}