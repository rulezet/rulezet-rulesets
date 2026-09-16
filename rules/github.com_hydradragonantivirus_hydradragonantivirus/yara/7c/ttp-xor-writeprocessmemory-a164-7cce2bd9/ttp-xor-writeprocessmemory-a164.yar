rule TTP_XOR_WriteProcessMemory_a164 {
  strings:
    $key_a164 = { f6 16 [2] c4 34 [2] c2 01 [2] ec 01 [2] d3 1d }

  condition:
    any of them
}