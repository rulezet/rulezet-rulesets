rule TTP_XOR_WriteProcessMemory_079f {
  strings:
    $key_079f = { 50 ed [2] 62 cf [2] 64 fa [2] 4a fa [2] 75 e6 }

  condition:
    any of them
}