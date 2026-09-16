rule TTP_XOR_WriteProcessMemory_a1c7 {
  strings:
    $key_a1c7 = { f6 b5 [2] c4 97 [2] c2 a2 [2] ec a2 [2] d3 be }

  condition:
    any of them
}