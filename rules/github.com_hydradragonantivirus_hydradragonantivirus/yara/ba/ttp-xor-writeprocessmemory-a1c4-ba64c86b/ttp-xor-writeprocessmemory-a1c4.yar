rule TTP_XOR_WriteProcessMemory_a1c4 {
  strings:
    $key_a1c4 = { f6 b6 [2] c4 94 [2] c2 a1 [2] ec a1 [2] d3 bd }

  condition:
    any of them
}