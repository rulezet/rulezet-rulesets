rule TTP_XOR_WriteProcessMemory_b6fe {
  strings:
    $key_b6fe = { e1 8c [2] d3 ae [2] d5 9b [2] fb 9b [2] c4 87 }

  condition:
    any of them
}