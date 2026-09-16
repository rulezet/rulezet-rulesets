rule TTP_XOR_WriteProcessMemory_90cd {
  strings:
    $key_90cd = { c7 bf [2] f5 9d [2] f3 a8 [2] dd a8 [2] e2 b4 }

  condition:
    any of them
}