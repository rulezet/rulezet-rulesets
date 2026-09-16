rule TTP_XOR_WriteProcessMemory_a1cd {
  strings:
    $key_a1cd = { f6 bf [2] c4 9d [2] c2 a8 [2] ec a8 [2] d3 b4 }

  condition:
    any of them
}