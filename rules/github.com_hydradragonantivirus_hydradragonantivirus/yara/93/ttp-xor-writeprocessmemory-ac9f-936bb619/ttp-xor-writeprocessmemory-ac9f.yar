rule TTP_XOR_WriteProcessMemory_ac9f {
  strings:
    $key_ac9f = { fb ed [2] c9 cf [2] cf fa [2] e1 fa [2] de e6 }

  condition:
    any of them
}