rule TTP_XOR_WriteProcessMemory_00bd {
  strings:
    $key_00bd = { 57 cf [2] 65 ed [2] 63 d8 [2] 4d d8 [2] 72 c4 }

  condition:
    any of them
}