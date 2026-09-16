rule TTP_XOR_WriteProcessMemory_d624 {
  strings:
    $key_d624 = { 81 56 [2] b3 74 [2] b5 41 [2] 9b 41 [2] a4 5d }

  condition:
    any of them
}