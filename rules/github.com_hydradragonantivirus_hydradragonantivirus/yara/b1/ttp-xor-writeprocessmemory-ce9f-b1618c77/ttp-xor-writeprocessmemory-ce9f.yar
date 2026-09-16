rule TTP_XOR_WriteProcessMemory_ce9f {
  strings:
    $key_ce9f = { 99 ed [2] ab cf [2] ad fa [2] 83 fa [2] bc e6 }

  condition:
    any of them
}