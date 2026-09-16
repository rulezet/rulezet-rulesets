rule TTP_XOR_WriteProcessMemory_0a2c {
  strings:
    $key_0a2c = { 5d 5e [2] 6f 7c [2] 69 49 [2] 47 49 [2] 78 55 }

  condition:
    any of them
}