rule TTP_XOR_WriteProcessMemory_05cd {
  strings:
    $key_05cd = { 52 bf [2] 60 9d [2] 66 a8 [2] 48 a8 [2] 77 b4 }

  condition:
    any of them
}