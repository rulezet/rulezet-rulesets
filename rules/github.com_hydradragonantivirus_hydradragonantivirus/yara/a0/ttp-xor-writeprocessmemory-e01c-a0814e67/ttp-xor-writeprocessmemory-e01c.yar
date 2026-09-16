rule TTP_XOR_WriteProcessMemory_e01c {
  strings:
    $key_e01c = { b7 6e [2] 85 4c [2] 83 79 [2] ad 79 [2] 92 65 }

  condition:
    any of them
}