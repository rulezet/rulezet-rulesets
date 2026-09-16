rule TTP_XOR_WriteProcessMemory_86bd {
  strings:
    $key_86bd = { d1 cf [2] e3 ed [2] e5 d8 [2] cb d8 [2] f4 c4 }

  condition:
    any of them
}