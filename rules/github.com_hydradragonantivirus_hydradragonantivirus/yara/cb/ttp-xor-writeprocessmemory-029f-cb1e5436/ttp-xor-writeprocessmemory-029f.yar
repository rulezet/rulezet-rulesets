rule TTP_XOR_WriteProcessMemory_029f {
  strings:
    $key_029f = { 55 ed [2] 67 cf [2] 61 fa [2] 4f fa [2] 70 e6 }

  condition:
    any of them
}