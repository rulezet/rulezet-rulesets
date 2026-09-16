rule TTP_XOR_WriteProcessMemory_a153 {
  strings:
    $key_a153 = { f6 21 [2] c4 03 [2] c2 36 [2] ec 36 [2] d3 2a }

  condition:
    any of them
}