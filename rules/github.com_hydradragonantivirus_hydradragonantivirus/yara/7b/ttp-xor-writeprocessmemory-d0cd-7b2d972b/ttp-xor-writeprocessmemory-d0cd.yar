rule TTP_XOR_WriteProcessMemory_d0cd {
  strings:
    $key_d0cd = { 87 bf [2] b5 9d [2] b3 a8 [2] 9d a8 [2] a2 b4 }

  condition:
    any of them
}