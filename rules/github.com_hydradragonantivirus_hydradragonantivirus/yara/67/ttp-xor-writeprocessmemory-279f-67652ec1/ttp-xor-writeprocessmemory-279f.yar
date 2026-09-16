rule TTP_XOR_WriteProcessMemory_279f {
  strings:
    $key_279f = { 70 ed [2] 42 cf [2] 44 fa [2] 6a fa [2] 55 e6 }

  condition:
    any of them
}