rule TTP_XOR_WriteProcessMemory_9e8c {
  strings:
    $key_9e8c = { c9 fe [2] fb dc [2] fd e9 [2] d3 e9 [2] ec f5 }

  condition:
    any of them
}