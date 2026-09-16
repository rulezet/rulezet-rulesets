rule TTP_XOR_WriteProcessMemory_f79f {
  strings:
    $key_f79f = { a0 ed [2] 92 cf [2] 94 fa [2] ba fa [2] 85 e6 }

  condition:
    any of them
}