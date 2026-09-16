rule TTP_XOR_WriteProcessMemory_09bd {
  strings:
    $key_09bd = { 5e cf [2] 6c ed [2] 6a d8 [2] 44 d8 [2] 7b c4 }

  condition:
    any of them
}