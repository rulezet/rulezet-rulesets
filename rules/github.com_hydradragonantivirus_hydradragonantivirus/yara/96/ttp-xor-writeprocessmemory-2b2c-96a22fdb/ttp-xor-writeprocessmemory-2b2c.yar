rule TTP_XOR_WriteProcessMemory_2b2c {
  strings:
    $key_2b2c = { 7c 5e [2] 4e 7c [2] 48 49 [2] 66 49 [2] 59 55 }

  condition:
    any of them
}