rule TTP_XOR_WriteProcessMemory_e6cd {
  strings:
    $key_e6cd = { b1 bf [2] 83 9d [2] 85 a8 [2] ab a8 [2] 94 b4 }

  condition:
    any of them
}