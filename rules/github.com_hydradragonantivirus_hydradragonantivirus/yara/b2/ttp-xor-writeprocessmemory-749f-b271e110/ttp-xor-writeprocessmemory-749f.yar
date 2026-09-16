rule TTP_XOR_WriteProcessMemory_749f {
  strings:
    $key_749f = { 23 ed [2] 11 cf [2] 17 fa [2] 39 fa [2] 06 e6 }

  condition:
    any of them
}