rule TTP_XOR_WriteProcessMemory_10bd {
  strings:
    $key_10bd = { 47 cf [2] 75 ed [2] 73 d8 [2] 5d d8 [2] 62 c4 }

  condition:
    any of them
}