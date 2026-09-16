rule TTP_XOR_WriteProcessMemory_55cd {
  strings:
    $key_55cd = { 02 bf [2] 30 9d [2] 36 a8 [2] 18 a8 [2] 27 b4 }

  condition:
    any of them
}