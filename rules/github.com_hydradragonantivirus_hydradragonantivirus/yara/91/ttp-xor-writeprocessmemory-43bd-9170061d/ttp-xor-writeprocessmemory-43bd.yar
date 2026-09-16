rule TTP_XOR_WriteProcessMemory_43bd {
  strings:
    $key_43bd = { 14 cf [2] 26 ed [2] 20 d8 [2] 0e d8 [2] 31 c4 }

  condition:
    any of them
}