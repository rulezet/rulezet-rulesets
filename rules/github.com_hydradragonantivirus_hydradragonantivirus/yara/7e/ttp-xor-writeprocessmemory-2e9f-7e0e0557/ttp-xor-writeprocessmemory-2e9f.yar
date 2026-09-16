rule TTP_XOR_WriteProcessMemory_2e9f {
  strings:
    $key_2e9f = { 79 ed [2] 4b cf [2] 4d fa [2] 63 fa [2] 5c e6 }

  condition:
    any of them
}