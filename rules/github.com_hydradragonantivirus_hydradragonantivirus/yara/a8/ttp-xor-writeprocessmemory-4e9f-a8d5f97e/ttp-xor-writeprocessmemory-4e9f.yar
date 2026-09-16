rule TTP_XOR_WriteProcessMemory_4e9f {
  strings:
    $key_4e9f = { 19 ed [2] 2b cf [2] 2d fa [2] 03 fa [2] 3c e6 }

  condition:
    any of them
}