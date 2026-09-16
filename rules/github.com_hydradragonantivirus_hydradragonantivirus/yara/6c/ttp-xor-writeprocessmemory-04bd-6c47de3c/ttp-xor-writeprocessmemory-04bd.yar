rule TTP_XOR_WriteProcessMemory_04bd {
  strings:
    $key_04bd = { 53 cf [2] 61 ed [2] 67 d8 [2] 49 d8 [2] 76 c4 }

  condition:
    any of them
}