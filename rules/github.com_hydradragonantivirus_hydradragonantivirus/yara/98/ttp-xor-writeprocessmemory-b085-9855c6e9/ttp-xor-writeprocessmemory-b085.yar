rule TTP_XOR_WriteProcessMemory_b085 {
  strings:
    $key_b085 = { e7 f7 [2] d5 d5 [2] d3 e0 [2] fd e0 [2] c2 fc }

  condition:
    any of them
}