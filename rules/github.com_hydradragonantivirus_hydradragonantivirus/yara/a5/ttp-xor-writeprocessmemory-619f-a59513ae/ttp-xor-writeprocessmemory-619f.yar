rule TTP_XOR_WriteProcessMemory_619f {
  strings:
    $key_619f = { 36 ed [2] 04 cf [2] 02 fa [2] 2c fa [2] 13 e6 }

  condition:
    any of them
}