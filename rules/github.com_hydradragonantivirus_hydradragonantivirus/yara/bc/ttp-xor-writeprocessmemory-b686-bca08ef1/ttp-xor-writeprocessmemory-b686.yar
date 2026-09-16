rule TTP_XOR_WriteProcessMemory_b686 {
  strings:
    $key_b686 = { e1 f4 [2] d3 d6 [2] d5 e3 [2] fb e3 [2] c4 ff }

  condition:
    any of them
}