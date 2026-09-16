rule TTP_XOR_WriteProcessMemory_a347 {
  strings:
    $key_a347 = { f4 35 [2] c6 17 [2] c0 22 [2] ee 22 [2] d1 3e }

  condition:
    any of them
}