rule TTP_XOR_WriteProcessMemory_3abd {
  strings:
    $key_3abd = { 6d cf [2] 5f ed [2] 59 d8 [2] 77 d8 [2] 48 c4 }

  condition:
    any of them
}