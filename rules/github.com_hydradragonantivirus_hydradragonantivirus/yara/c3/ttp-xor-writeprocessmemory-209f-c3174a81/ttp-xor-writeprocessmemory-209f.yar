rule TTP_XOR_WriteProcessMemory_209f {
  strings:
    $key_209f = { 77 ed [2] 45 cf [2] 43 fa [2] 6d fa [2] 52 e6 }

  condition:
    any of them
}