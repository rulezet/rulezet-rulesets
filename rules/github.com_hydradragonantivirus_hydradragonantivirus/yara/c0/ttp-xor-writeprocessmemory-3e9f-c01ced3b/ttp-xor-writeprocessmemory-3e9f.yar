rule TTP_XOR_WriteProcessMemory_3e9f {
  strings:
    $key_3e9f = { 69 ed [2] 5b cf [2] 5d fa [2] 73 fa [2] 4c e6 }

  condition:
    any of them
}