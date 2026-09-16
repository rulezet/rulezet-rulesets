rule TTP_XOR_WriteProcessMemory_059f {
  strings:
    $key_059f = { 52 ed [2] 60 cf [2] 66 fa [2] 48 fa [2] 77 e6 }

  condition:
    any of them
}