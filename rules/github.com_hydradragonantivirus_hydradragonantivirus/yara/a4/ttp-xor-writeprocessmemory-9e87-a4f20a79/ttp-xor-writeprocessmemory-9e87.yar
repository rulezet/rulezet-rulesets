rule TTP_XOR_WriteProcessMemory_9e87 {
  strings:
    $key_9e87 = { c9 f5 [2] fb d7 [2] fd e2 [2] d3 e2 [2] ec fe }

  condition:
    any of them
}