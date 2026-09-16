rule TTP_XOR_WriteProcessMemory_01cd {
  strings:
    $key_01cd = { 56 bf [2] 64 9d [2] 62 a8 [2] 4c a8 [2] 73 b4 }

  condition:
    any of them
}