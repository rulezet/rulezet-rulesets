rule TTP_XOR_WriteProcessMemory_6923 {
  strings:
    $key_6923 = { 3e 51 [2] 0c 73 [2] 0a 46 [2] 24 46 [2] 1b 5a }

  condition:
    any of them
}