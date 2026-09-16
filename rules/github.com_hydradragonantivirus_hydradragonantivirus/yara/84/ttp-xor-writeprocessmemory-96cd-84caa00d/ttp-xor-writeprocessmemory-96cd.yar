rule TTP_XOR_WriteProcessMemory_96cd {
  strings:
    $key_96cd = { c1 bf [2] f3 9d [2] f5 a8 [2] db a8 [2] e4 b4 }

  condition:
    any of them
}