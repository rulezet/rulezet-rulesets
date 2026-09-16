rule TTP_XOR_WriteProcessMemory_10cd {
  strings:
    $key_10cd = { 47 bf [2] 75 9d [2] 73 a8 [2] 5d a8 [2] 62 b4 }

  condition:
    any of them
}