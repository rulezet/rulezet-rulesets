rule TTP_XOR_WriteProcessMemory_149f {
  strings:
    $key_149f = { 43 ed [2] 71 cf [2] 77 fa [2] 59 fa [2] 66 e6 }

  condition:
    any of them
}