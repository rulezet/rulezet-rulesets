rule TTP_XOR_WriteProcessMemory_b647 {
  strings:
    $key_b647 = { e1 35 [2] d3 17 [2] d5 22 [2] fb 22 [2] c4 3e }

  condition:
    any of them
}