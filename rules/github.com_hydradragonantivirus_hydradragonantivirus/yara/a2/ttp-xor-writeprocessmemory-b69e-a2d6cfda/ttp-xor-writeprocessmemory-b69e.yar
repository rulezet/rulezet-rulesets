rule TTP_XOR_WriteProcessMemory_b69e {
  strings:
    $key_b69e = { e1 ec [2] d3 ce [2] d5 fb [2] fb fb [2] c4 e7 }

  condition:
    any of them
}