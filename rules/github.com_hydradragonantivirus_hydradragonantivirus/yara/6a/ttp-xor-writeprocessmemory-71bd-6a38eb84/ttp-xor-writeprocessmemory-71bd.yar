rule TTP_XOR_WriteProcessMemory_71bd {
  strings:
    $key_71bd = { 26 cf [2] 14 ed [2] 12 d8 [2] 3c d8 [2] 03 c4 }

  condition:
    any of them
}