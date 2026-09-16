rule TTP_XOR_WriteProcessMemory_92b6 {
  strings:
    $key_92b6 = { c5 c4 [2] f7 e6 [2] f1 d3 [2] df d3 [2] e0 cf }

  condition:
    any of them
}