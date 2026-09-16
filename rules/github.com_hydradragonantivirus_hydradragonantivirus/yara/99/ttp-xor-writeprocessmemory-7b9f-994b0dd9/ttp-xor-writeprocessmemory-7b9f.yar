rule TTP_XOR_WriteProcessMemory_7b9f {
  strings:
    $key_7b9f = { 2c ed [2] 1e cf [2] 18 fa [2] 36 fa [2] 09 e6 }

  condition:
    any of them
}