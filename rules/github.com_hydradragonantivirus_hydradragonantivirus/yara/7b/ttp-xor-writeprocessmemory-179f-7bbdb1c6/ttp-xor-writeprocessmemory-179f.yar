rule TTP_XOR_WriteProcessMemory_179f {
  strings:
    $key_179f = { 40 ed [2] 72 cf [2] 74 fa [2] 5a fa [2] 65 e6 }

  condition:
    any of them
}