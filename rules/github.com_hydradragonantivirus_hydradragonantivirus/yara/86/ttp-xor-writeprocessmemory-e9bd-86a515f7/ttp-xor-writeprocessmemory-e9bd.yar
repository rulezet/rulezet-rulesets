rule TTP_XOR_WriteProcessMemory_e9bd {
  strings:
    $key_e9bd = { be cf [2] 8c ed [2] 8a d8 [2] a4 d8 [2] 9b c4 }

  condition:
    any of them
}