rule TTP_XOR_WriteProcessMemory_369f {
  strings:
    $key_369f = { 61 ed [2] 53 cf [2] 55 fa [2] 7b fa [2] 44 e6 }

  condition:
    any of them
}