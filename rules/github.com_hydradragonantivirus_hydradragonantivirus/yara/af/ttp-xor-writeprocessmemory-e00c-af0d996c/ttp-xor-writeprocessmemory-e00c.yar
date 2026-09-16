rule TTP_XOR_WriteProcessMemory_e00c {
  strings:
    $key_e00c = { b7 7e [2] 85 5c [2] 83 69 [2] ad 69 [2] 92 75 }

  condition:
    any of them
}