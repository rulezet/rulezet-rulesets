rule TTP_XOR_WriteProcessMemory_94b6 {
  strings:
    $key_94b6 = { c3 c4 [2] f1 e6 [2] f7 d3 [2] d9 d3 [2] e6 cf }

  condition:
    any of them
}