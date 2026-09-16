rule TTP_XOR_WriteProcessMemory_7e9f {
  strings:
    $key_7e9f = { 29 ed [2] 1b cf [2] 1d fa [2] 33 fa [2] 0c e6 }

  condition:
    any of them
}