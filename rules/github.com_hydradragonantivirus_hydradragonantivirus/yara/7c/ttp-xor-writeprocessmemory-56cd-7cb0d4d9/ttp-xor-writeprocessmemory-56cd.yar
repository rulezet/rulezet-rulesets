rule TTP_XOR_WriteProcessMemory_56cd {
  strings:
    $key_56cd = { 01 bf [2] 33 9d [2] 35 a8 [2] 1b a8 [2] 24 b4 }

  condition:
    any of them
}