rule TTP_XOR_WriteProcessMemory_f9bd {
  strings:
    $key_f9bd = { ae cf [2] 9c ed [2] 9a d8 [2] b4 d8 [2] 8b c4 }

  condition:
    any of them
}