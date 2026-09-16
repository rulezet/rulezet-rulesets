rule TTP_XOR_WriteProcessMemory_b888 {
  strings:
    $key_b888 = { ef fa [2] dd d8 [2] db ed [2] f5 ed [2] ca f1 }

  condition:
    any of them
}