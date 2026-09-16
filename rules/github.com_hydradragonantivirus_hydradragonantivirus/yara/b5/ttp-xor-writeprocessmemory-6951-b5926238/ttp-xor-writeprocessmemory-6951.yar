rule TTP_XOR_WriteProcessMemory_6951 {
  strings:
    $key_6951 = { 3e 23 [2] 0c 01 [2] 0a 34 [2] 24 34 [2] 1b 28 }

  condition:
    any of them
}