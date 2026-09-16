rule TTP_XOR_WriteProcessMemory_5b9f {
  strings:
    $key_5b9f = { 0c ed [2] 3e cf [2] 38 fa [2] 16 fa [2] 29 e6 }

  condition:
    any of them
}