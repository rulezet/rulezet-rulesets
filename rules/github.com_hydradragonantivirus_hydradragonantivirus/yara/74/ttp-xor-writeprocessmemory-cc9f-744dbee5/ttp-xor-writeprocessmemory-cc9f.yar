rule TTP_XOR_WriteProcessMemory_cc9f {
  strings:
    $key_cc9f = { 9b ed [2] a9 cf [2] af fa [2] 81 fa [2] be e6 }

  condition:
    any of them
}