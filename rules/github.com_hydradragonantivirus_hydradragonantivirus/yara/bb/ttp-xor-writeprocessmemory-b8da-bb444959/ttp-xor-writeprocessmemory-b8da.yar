rule TTP_XOR_WriteProcessMemory_b8da {
  strings:
    $key_b8da = { ef a8 [2] dd 8a [2] db bf [2] f5 bf [2] ca a3 }

  condition:
    any of them
}