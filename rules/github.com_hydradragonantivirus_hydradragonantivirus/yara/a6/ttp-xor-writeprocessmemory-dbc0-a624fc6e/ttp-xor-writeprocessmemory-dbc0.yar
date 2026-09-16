rule TTP_XOR_WriteProcessMemory_dbc0 {
  strings:
    $key_dbc0 = { 8c b2 [2] be 90 [2] b8 a5 [2] 96 a5 [2] a9 b9 }

  condition:
    any of them
}