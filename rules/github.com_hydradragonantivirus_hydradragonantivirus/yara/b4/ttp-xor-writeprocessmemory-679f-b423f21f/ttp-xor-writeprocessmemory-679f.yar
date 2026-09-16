rule TTP_XOR_WriteProcessMemory_679f {
  strings:
    $key_679f = { 30 ed [2] 02 cf [2] 04 fa [2] 2a fa [2] 15 e6 }

  condition:
    any of them
}