rule TTP_XOR_WriteProcessMemory_dbc8 {
  strings:
    $key_dbc8 = { 8c ba [2] be 98 [2] b8 ad [2] 96 ad [2] a9 b1 }

  condition:
    any of them
}