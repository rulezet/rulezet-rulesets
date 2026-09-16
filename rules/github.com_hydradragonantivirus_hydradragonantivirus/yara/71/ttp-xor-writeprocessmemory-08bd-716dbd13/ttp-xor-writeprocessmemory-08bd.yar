rule TTP_XOR_WriteProcessMemory_08bd {
  strings:
    $key_08bd = { 5f cf [2] 6d ed [2] 6b d8 [2] 45 d8 [2] 7a c4 }

  condition:
    any of them
}