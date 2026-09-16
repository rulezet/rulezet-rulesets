rule TTP_XOR_WriteProcessMemory_a157 {
  strings:
    $key_a157 = { f6 25 [2] c4 07 [2] c2 32 [2] ec 32 [2] d3 2e }

  condition:
    any of them
}