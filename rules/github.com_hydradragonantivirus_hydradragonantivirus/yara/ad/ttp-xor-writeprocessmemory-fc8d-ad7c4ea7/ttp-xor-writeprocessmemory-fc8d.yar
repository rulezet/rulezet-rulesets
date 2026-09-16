rule TTP_XOR_WriteProcessMemory_fc8d {
  strings:
    $key_fc8d = { ab ff [2] 99 dd [2] 9f e8 [2] b1 e8 [2] 8e f4 }

  condition:
    any of them
}