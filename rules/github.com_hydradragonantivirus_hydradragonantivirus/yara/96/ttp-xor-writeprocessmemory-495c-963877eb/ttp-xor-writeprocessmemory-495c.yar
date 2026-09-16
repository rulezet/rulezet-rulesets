rule TTP_XOR_WriteProcessMemory_495c {
  strings:
    $key_495c = { 1e 2e [2] 2c 0c [2] 2a 39 [2] 04 39 [2] 3b 25 }

  condition:
    any of them
}