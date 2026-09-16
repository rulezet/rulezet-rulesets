rule TTP_XOR_WriteProcessMemory_dbc7 {
  strings:
    $key_dbc7 = { 8c b5 [2] be 97 [2] b8 a2 [2] 96 a2 [2] a9 be }

  condition:
    any of them
}