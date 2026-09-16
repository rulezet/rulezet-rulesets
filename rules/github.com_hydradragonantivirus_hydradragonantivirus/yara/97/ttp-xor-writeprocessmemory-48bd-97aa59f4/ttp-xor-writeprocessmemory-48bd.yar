rule TTP_XOR_WriteProcessMemory_48bd {
  strings:
    $key_48bd = { 1f cf [2] 2d ed [2] 2b d8 [2] 05 d8 [2] 3a c4 }

  condition:
    any of them
}