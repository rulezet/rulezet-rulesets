rule TTP_XOR_WriteProcessMemory_38bd {
  strings:
    $key_38bd = { 6f cf [2] 5d ed [2] 5b d8 [2] 75 d8 [2] 4a c4 }

  condition:
    any of them
}