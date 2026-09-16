rule TTP_XOR_WriteProcessMemory_999f {
  strings:
    $key_999f = { ce ed [2] fc cf [2] fa fa [2] d4 fa [2] eb e6 }

  condition:
    any of them
}