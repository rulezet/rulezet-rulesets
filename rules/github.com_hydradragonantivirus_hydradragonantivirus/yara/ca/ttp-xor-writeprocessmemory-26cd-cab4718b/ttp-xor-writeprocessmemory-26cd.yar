rule TTP_XOR_WriteProcessMemory_26cd {
  strings:
    $key_26cd = { 71 bf [2] 43 9d [2] 45 a8 [2] 6b a8 [2] 54 b4 }

  condition:
    any of them
}