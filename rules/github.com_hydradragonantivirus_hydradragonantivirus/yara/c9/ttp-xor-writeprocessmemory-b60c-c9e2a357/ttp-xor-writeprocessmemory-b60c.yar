rule TTP_XOR_WriteProcessMemory_b60c {
  strings:
    $key_b60c = { e1 7e [2] d3 5c [2] d5 69 [2] fb 69 [2] c4 75 }

  condition:
    any of them
}