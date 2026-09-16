rule TTP_XOR_WriteProcessMemory_0c7c {
  strings:
    $key_0c7c = { 5b 0e [2] 69 2c [2] 6f 19 [2] 41 19 [2] 7e 05 }

  condition:
    any of them
}