rule TTP_XOR_WriteProcessMemory_d5cd {
  strings:
    $key_d5cd = { 82 bf [2] b0 9d [2] b6 a8 [2] 98 a8 [2] a7 b4 }

  condition:
    any of them
}