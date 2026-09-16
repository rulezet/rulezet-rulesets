rule TTP_XOR_WriteProcessMemory_5abd {
  strings:
    $key_5abd = { 0d cf [2] 3f ed [2] 39 d8 [2] 17 d8 [2] 28 c4 }

  condition:
    any of them
}