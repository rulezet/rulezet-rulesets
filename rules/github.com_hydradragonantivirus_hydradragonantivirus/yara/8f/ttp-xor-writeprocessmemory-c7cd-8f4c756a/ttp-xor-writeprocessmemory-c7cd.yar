rule TTP_XOR_WriteProcessMemory_c7cd {
  strings:
    $key_c7cd = { 90 bf [2] a2 9d [2] a4 a8 [2] 8a a8 [2] b5 b4 }

  condition:
    any of them
}