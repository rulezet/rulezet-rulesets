rule TTP_XOR_WriteProcessMemory_a1d7 {
  strings:
    $key_a1d7 = { f6 a5 [2] c4 87 [2] c2 b2 [2] ec b2 [2] d3 ae }

  condition:
    any of them
}