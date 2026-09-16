rule TTP_XOR_WriteProcessMemory_44bd {
  strings:
    $key_44bd = { 13 cf [2] 21 ed [2] 27 d8 [2] 09 d8 [2] 36 c4 }

  condition:
    any of them
}