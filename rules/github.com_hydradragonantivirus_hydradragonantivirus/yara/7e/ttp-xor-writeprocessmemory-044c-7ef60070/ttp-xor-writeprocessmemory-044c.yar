rule TTP_XOR_WriteProcessMemory_044c {
  strings:
    $key_044c = { 53 3e [2] 61 1c [2] 67 29 [2] 49 29 [2] 76 35 }

  condition:
    any of them
}