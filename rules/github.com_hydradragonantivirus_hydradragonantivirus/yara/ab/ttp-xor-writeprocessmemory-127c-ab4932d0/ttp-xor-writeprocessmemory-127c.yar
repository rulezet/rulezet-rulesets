rule TTP_XOR_WriteProcessMemory_127c {
  strings:
    $key_127c = { 45 0e [2] 77 2c [2] 71 19 [2] 5f 19 [2] 60 05 }

  condition:
    any of them
}