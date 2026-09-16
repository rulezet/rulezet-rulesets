rule TTP_XOR_WriteProcessMemory_30bd {
  strings:
    $key_30bd = { 67 cf [2] 55 ed [2] 53 d8 [2] 7d d8 [2] 42 c4 }

  condition:
    any of them
}