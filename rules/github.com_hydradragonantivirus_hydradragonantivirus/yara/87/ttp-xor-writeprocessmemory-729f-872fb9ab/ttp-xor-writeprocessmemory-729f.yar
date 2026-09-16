rule TTP_XOR_WriteProcessMemory_729f {
  strings:
    $key_729f = { 25 ed [2] 17 cf [2] 11 fa [2] 3f fa [2] 00 e6 }

  condition:
    any of them
}