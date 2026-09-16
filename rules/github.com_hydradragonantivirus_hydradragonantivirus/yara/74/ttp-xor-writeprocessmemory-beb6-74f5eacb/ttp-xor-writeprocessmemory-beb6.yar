rule TTP_XOR_WriteProcessMemory_beb6 {
  strings:
    $key_beb6 = { e9 c4 [2] db e6 [2] dd d3 [2] f3 d3 [2] cc cf }

  condition:
    any of them
}