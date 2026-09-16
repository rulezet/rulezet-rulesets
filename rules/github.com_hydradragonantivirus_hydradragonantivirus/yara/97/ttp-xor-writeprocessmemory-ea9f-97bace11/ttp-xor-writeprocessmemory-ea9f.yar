rule TTP_XOR_WriteProcessMemory_ea9f {
  strings:
    $key_ea9f = { bd ed [2] 8f cf [2] 89 fa [2] a7 fa [2] 98 e6 }

  condition:
    any of them
}