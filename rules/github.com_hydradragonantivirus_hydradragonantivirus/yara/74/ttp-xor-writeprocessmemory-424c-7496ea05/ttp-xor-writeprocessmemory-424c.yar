rule TTP_XOR_WriteProcessMemory_424c {
  strings:
    $key_424c = { 15 3e [2] 27 1c [2] 21 29 [2] 0f 29 [2] 30 35 }

  condition:
    any of them
}