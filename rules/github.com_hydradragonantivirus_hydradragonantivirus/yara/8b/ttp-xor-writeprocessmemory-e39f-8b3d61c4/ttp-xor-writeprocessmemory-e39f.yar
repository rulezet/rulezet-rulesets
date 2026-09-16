rule TTP_XOR_WriteProcessMemory_e39f {
  strings:
    $key_e39f = { b4 ed [2] 86 cf [2] 80 fa [2] ae fa [2] 91 e6 }

  condition:
    any of them
}