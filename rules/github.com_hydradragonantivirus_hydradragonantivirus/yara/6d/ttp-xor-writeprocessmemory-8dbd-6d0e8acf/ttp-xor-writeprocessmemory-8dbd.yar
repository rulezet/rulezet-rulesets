rule TTP_XOR_WriteProcessMemory_8dbd {
  strings:
    $key_8dbd = { da cf [2] e8 ed [2] ee d8 [2] c0 d8 [2] ff c4 }

  condition:
    any of them
}