rule TTP_XOR_WriteProcessMemory_4b9f {
  strings:
    $key_4b9f = { 1c ed [2] 2e cf [2] 28 fa [2] 06 fa [2] 39 e6 }

  condition:
    any of them
}