rule TTP_XOR_WriteProcessMemory_879f {
  strings:
    $key_879f = { d0 ed [2] e2 cf [2] e4 fa [2] ca fa [2] f5 e6 }

  condition:
    any of them
}