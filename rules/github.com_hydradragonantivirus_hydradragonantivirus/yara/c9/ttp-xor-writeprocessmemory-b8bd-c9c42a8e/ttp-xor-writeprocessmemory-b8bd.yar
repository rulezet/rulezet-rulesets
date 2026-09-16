rule TTP_XOR_WriteProcessMemory_b8bd {
  strings:
    $key_b8bd = { ef cf [2] dd ed [2] db d8 [2] f5 d8 [2] ca c4 }

  condition:
    any of them
}