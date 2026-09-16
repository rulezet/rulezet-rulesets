rule TTP_XOR_WriteProcessMemory_9883 {
  strings:
    $key_9883 = { cf f1 [2] fd d3 [2] fb e6 [2] d5 e6 [2] ea fa }

  condition:
    any of them
}