rule TTP_XOR_WriteProcessMemory_134c {
  strings:
    $key_134c = { 44 3e [2] 76 1c [2] 70 29 [2] 5e 29 [2] 61 35 }

  condition:
    any of them
}