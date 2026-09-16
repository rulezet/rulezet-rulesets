rule TTP_XOR_WriteProcessMemory_05bd {
  strings:
    $key_05bd = { 52 cf [2] 60 ed [2] 66 d8 [2] 48 d8 [2] 77 c4 }

  condition:
    any of them
}