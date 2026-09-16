rule TTP_XOR_WriteProcessMemory_7e49 {
  strings:
    $key_7e49 = { 29 3b [2] 1b 19 [2] 1d 2c [2] 33 2c [2] 0c 30 }

  condition:
    any of them
}