rule TTP_XOR_WriteProcessMemory_a137 {
  strings:
    $key_a137 = { f6 45 [2] c4 67 [2] c2 52 [2] ec 52 [2] d3 4e }

  condition:
    any of them
}