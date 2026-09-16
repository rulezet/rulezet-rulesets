rule TTP_XOR_WriteProcessMemory_c2cd {
  strings:
    $key_c2cd = { 95 bf [2] a7 9d [2] a1 a8 [2] 8f a8 [2] b0 b4 }

  condition:
    any of them
}