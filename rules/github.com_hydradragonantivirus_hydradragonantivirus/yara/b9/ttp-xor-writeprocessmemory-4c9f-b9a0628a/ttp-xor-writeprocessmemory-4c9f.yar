rule TTP_XOR_WriteProcessMemory_4c9f {
  strings:
    $key_4c9f = { 1b ed [2] 29 cf [2] 2f fa [2] 01 fa [2] 3e e6 }

  condition:
    any of them
}