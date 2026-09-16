rule TTP_XOR_WriteProcessMemory_efdd {
  strings:
    $key_efdd = { b8 af [2] 8a 8d [2] 8c b8 [2] a2 b8 [2] 9d a4 }

  condition:
    any of them
}