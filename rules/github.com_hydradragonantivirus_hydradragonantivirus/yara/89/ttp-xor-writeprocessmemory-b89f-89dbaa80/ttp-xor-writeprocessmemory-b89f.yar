rule TTP_XOR_WriteProcessMemory_b89f {
  strings:
    $key_b89f = { ef ed [2] dd cf [2] db fa [2] f5 fa [2] ca e6 }

  condition:
    any of them
}