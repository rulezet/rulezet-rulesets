rule TTP_XOR_WriteProcessMemory_b083 {
  strings:
    $key_b083 = { e7 f1 [2] d5 d3 [2] d3 e6 [2] fd e6 [2] c2 fa }

  condition:
    any of them
}