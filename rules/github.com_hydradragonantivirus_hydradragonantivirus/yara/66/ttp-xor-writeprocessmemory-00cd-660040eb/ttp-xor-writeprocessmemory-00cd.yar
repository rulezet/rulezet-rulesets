rule TTP_XOR_WriteProcessMemory_00cd {
  strings:
    $key_00cd = { 57 bf [2] 65 9d [2] 63 a8 [2] 4d a8 [2] 72 b4 }

  condition:
    any of them
}