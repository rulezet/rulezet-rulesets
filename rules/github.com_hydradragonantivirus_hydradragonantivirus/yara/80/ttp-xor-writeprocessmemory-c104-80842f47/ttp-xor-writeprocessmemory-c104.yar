rule TTP_XOR_WriteProcessMemory_c104 {
  strings:
    $key_c104 = { 96 76 [2] a4 54 [2] a2 61 [2] 8c 61 [2] b3 7d }

  condition:
    any of them
}