rule TTP_XOR_WriteProcessMemory_d8bd {
  strings:
    $key_d8bd = { 8f cf [2] bd ed [2] bb d8 [2] 95 d8 [2] aa c4 }

  condition:
    any of them
}