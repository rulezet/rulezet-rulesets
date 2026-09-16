rule TTP_XOR_WriteProcessMemory_39bd {
  strings:
    $key_39bd = { 6e cf [2] 5c ed [2] 5a d8 [2] 74 d8 [2] 4b c4 }

  condition:
    any of them
}