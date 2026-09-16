rule TTP_XOR_WriteProcessMemory_aaaa {
  strings:
    $key_aaaa = { fd d8 [2] cf fa [2] c9 cf [2] e7 cf [2] d8 d3 }

  condition:
    any of them
}