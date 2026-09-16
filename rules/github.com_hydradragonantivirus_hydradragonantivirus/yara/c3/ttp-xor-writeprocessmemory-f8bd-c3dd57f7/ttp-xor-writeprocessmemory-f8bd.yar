rule TTP_XOR_WriteProcessMemory_f8bd {
  strings:
    $key_f8bd = { af cf [2] 9d ed [2] 9b d8 [2] b5 d8 [2] 8a c4 }

  condition:
    any of them
}