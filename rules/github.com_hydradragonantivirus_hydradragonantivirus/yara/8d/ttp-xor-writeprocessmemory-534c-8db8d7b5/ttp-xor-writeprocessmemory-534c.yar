rule TTP_XOR_WriteProcessMemory_534c {
  strings:
    $key_534c = { 04 3e [2] 36 1c [2] 30 29 [2] 1e 29 [2] 21 35 }

  condition:
    any of them
}