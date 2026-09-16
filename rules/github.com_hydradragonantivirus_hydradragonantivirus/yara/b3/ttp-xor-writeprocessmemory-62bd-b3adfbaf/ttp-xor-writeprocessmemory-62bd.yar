rule TTP_XOR_WriteProcessMemory_62bd {
  strings:
    $key_62bd = { 35 cf [2] 07 ed [2] 01 d8 [2] 2f d8 [2] 10 c4 }

  condition:
    any of them
}