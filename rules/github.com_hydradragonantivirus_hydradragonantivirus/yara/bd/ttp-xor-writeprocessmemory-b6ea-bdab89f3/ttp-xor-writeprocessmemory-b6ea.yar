rule TTP_XOR_WriteProcessMemory_b6ea {
  strings:
    $key_b6ea = { e1 98 [2] d3 ba [2] d5 8f [2] fb 8f [2] c4 93 }

  condition:
    any of them
}