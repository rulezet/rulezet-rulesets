rule TTP_XOR_WriteProcessMemory_012c {
  strings:
    $key_012c = { 56 5e [2] 64 7c [2] 62 49 [2] 4c 49 [2] 73 55 }

  condition:
    any of them
}