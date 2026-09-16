rule TTP_XOR_WriteProcessMemory_6fdd {
  strings:
    $key_6fdd = { 38 af [2] 0a 8d [2] 0c b8 [2] 22 b8 [2] 1d a4 }

  condition:
    any of them
}