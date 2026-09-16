rule TTP_XOR_WriteProcessMemory_b6d8 {
  strings:
    $key_b6d8 = { e1 aa [2] d3 88 [2] d5 bd [2] fb bd [2] c4 a1 }

  condition:
    any of them
}