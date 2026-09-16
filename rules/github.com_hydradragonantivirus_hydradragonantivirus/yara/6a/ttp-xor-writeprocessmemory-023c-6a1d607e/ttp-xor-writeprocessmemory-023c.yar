rule TTP_XOR_WriteProcessMemory_023c {
  strings:
    $key_023c = { 55 4e [2] 67 6c [2] 61 59 [2] 4f 59 [2] 70 45 }

  condition:
    any of them
}