rule TTP_XOR_WriteProcessMemory_5e5c {
  strings:
    $key_5e5c = { 09 2e [2] 3b 0c [2] 3d 39 [2] 13 39 [2] 2c 25 }

  condition:
    any of them
}