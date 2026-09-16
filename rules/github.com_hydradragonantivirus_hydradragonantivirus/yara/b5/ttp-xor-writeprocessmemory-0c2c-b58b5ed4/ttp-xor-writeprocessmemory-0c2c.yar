rule TTP_XOR_WriteProcessMemory_0c2c {
  strings:
    $key_0c2c = { 5b 5e [2] 69 7c [2] 6f 49 [2] 41 49 [2] 7e 55 }

  condition:
    any of them
}