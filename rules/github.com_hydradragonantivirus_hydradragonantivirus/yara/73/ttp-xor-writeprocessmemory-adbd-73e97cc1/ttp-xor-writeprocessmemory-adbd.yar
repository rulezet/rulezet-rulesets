rule TTP_XOR_WriteProcessMemory_adbd {
  strings:
    $key_adbd = { fa cf [2] c8 ed [2] ce d8 [2] e0 d8 [2] df c4 }

  condition:
    any of them
}