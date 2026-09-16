rule TTP_XOR_WriteProcessMemory_bdbd {
  strings:
    $key_bdbd = { ea cf [2] d8 ed [2] de d8 [2] f0 d8 [2] cf c4 }

  condition:
    any of them
}