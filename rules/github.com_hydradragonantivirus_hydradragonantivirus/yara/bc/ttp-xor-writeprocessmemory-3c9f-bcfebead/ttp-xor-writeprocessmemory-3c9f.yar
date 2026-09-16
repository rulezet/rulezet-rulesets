rule TTP_XOR_WriteProcessMemory_3c9f {
  strings:
    $key_3c9f = { 6b ed [2] 59 cf [2] 5f fa [2] 71 fa [2] 4e e6 }

  condition:
    any of them
}