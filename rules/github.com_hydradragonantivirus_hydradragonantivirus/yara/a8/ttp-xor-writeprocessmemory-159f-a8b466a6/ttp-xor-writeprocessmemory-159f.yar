rule TTP_XOR_WriteProcessMemory_159f {
  strings:
    $key_159f = { 42 ed [2] 70 cf [2] 76 fa [2] 58 fa [2] 67 e6 }

  condition:
    any of them
}