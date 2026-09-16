rule TTP_XOR_WriteProcessMemory_514c {
  strings:
    $key_514c = { 06 3e [2] 34 1c [2] 32 29 [2] 1c 29 [2] 23 35 }

  condition:
    any of them
}