rule TTP_XOR_WriteProcessMemory_732c {
  strings:
    $key_732c = { 24 5e [2] 16 7c [2] 10 49 [2] 3e 49 [2] 01 55 }

  condition:
    any of them
}