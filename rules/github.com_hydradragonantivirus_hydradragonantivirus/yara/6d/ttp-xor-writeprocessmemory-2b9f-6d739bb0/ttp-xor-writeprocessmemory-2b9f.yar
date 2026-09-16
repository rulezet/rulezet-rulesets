rule TTP_XOR_WriteProcessMemory_2b9f {
  strings:
    $key_2b9f = { 7c ed [2] 4e cf [2] 48 fa [2] 66 fa [2] 59 e6 }

  condition:
    any of them
}