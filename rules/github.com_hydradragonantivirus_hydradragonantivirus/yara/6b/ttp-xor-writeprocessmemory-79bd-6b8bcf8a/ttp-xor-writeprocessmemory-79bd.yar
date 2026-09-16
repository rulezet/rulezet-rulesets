rule TTP_XOR_WriteProcessMemory_79bd {
  strings:
    $key_79bd = { 2e cf [2] 1c ed [2] 1a d8 [2] 34 d8 [2] 0b c4 }

  condition:
    any of them
}