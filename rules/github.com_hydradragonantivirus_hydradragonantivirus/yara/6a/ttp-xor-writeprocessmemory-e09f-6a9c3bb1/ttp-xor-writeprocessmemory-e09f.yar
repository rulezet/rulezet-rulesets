rule TTP_XOR_WriteProcessMemory_e09f {
  strings:
    $key_e09f = { b7 ed [2] 85 cf [2] 83 fa [2] ad fa [2] 92 e6 }

  condition:
    any of them
}