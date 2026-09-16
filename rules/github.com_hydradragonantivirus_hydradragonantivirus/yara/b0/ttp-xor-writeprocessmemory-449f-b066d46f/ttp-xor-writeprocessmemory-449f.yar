rule TTP_XOR_WriteProcessMemory_449f {
  strings:
    $key_449f = { 13 ed [2] 21 cf [2] 27 fa [2] 09 fa [2] 36 e6 }

  condition:
    any of them
}