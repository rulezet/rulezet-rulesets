rule TTP_XOR_WriteProcessMemory_f39f {
  strings:
    $key_f39f = { a4 ed [2] 96 cf [2] 90 fa [2] be fa [2] 81 e6 }

  condition:
    any of them
}