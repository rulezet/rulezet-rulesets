rule TTP_XOR_WriteProcessMemory_1c9f {
  strings:
    $key_1c9f = { 4b ed [2] 79 cf [2] 7f fa [2] 51 fa [2] 6e e6 }

  condition:
    any of them
}