rule TTP_XOR_WriteProcessMemory_737c {
  strings:
    $key_737c = { 24 0e [2] 16 2c [2] 10 19 [2] 3e 19 [2] 01 05 }

  condition:
    any of them
}