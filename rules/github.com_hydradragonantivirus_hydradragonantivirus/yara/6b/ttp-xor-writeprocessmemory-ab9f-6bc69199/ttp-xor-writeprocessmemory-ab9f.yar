rule TTP_XOR_WriteProcessMemory_ab9f {
  strings:
    $key_ab9f = { fc ed [2] ce cf [2] c8 fa [2] e6 fa [2] d9 e6 }

  condition:
    any of them
}