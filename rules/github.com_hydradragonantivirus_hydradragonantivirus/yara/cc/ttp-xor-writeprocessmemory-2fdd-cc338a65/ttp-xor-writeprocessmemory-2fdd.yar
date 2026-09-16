rule TTP_XOR_WriteProcessMemory_2fdd {
  strings:
    $key_2fdd = { 78 af [2] 4a 8d [2] 4c b8 [2] 62 b8 [2] 5d a4 }

  condition:
    any of them
}