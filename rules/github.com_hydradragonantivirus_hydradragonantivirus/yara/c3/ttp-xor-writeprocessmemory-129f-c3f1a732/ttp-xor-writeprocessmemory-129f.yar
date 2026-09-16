rule TTP_XOR_WriteProcessMemory_129f {
  strings:
    $key_129f = { 45 ed [2] 77 cf [2] 71 fa [2] 5f fa [2] 60 e6 }

  condition:
    any of them
}