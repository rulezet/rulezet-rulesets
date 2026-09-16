rule TTP_XOR_WriteProcessMemory_f5cd {
  strings:
    $key_f5cd = { a2 bf [2] 90 9d [2] 96 a8 [2] b8 a8 [2] 87 b4 }

  condition:
    any of them
}