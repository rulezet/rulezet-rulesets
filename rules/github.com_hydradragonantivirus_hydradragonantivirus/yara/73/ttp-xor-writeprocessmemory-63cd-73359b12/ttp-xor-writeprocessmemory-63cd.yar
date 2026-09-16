rule TTP_XOR_WriteProcessMemory_63cd {
  strings:
    $key_63cd = { 34 bf [2] 06 9d [2] 00 a8 [2] 2e a8 [2] 11 b4 }

  condition:
    any of them
}