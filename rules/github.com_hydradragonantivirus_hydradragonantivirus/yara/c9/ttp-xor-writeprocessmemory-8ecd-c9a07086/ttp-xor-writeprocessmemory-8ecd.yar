rule TTP_XOR_WriteProcessMemory_8ecd {
  strings:
    $key_8ecd = { d9 bf [2] eb 9d [2] ed a8 [2] c3 a8 [2] fc b4 }

  condition:
    any of them
}