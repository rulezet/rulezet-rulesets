rule TTP_XOR_WriteProcessMemory_989c {
  strings:
    $key_989c = { cf ee [2] fd cc [2] fb f9 [2] d5 f9 [2] ea e5 }

  condition:
    any of them
}