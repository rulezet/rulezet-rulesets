rule TTP_XOR_WriteProcessMemory_669f {
  strings:
    $key_669f = { 31 ed [2] 03 cf [2] 05 fa [2] 2b fa [2] 14 e6 }

  condition:
    any of them
}