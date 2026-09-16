rule TTP_XOR_WriteProcessMemory_c4cd {
  strings:
    $key_c4cd = { 93 bf [2] a1 9d [2] a7 a8 [2] 89 a8 [2] b6 b4 }

  condition:
    any of them
}