rule TTP_XOR_WriteProcessMemory_629f {
  strings:
    $key_629f = { 35 ed [2] 07 cf [2] 01 fa [2] 2f fa [2] 10 e6 }

  condition:
    any of them
}