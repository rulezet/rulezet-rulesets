rule TTP_XOR_WriteProcessMemory_919f {
  strings:
    $key_919f = { c6 ed [2] f4 cf [2] f2 fa [2] dc fa [2] e3 e6 }

  condition:
    any of them
}