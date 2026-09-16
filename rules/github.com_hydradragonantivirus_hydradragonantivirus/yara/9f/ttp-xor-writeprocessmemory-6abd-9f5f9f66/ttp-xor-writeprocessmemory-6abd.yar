rule TTP_XOR_WriteProcessMemory_6abd {
  strings:
    $key_6abd = { 3d cf [2] 0f ed [2] 09 d8 [2] 27 d8 [2] 18 c4 }

  condition:
    any of them
}