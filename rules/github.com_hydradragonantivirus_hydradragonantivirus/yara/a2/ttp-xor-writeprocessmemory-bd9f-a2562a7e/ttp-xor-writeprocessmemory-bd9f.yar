rule TTP_XOR_WriteProcessMemory_bd9f {
  strings:
    $key_bd9f = { ea ed [2] d8 cf [2] de fa [2] f0 fa [2] cf e6 }

  condition:
    any of them
}