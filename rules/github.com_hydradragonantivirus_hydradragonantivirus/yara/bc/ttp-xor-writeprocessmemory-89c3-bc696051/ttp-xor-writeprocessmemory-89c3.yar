rule TTP_XOR_WriteProcessMemory_89c3 {
  strings:
    $key_89c3 = { de b1 [2] ec 93 [2] ea a6 [2] c4 a6 [2] fb ba }

  condition:
    any of them
}