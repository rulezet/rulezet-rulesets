rule TTP_XOR_WriteProcessMemory_9887 {
  strings:
    $key_9887 = { cf f5 [2] fd d7 [2] fb e2 [2] d5 e2 [2] ea fe }

  condition:
    any of them
}