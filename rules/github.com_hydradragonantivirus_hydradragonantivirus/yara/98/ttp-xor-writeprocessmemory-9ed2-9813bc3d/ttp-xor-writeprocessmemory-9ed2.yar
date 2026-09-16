rule TTP_XOR_WriteProcessMemory_9ed2 {
  strings:
    $key_9ed2 = { c9 a0 [2] fb 82 [2] fd b7 [2] d3 b7 [2] ec ab }

  condition:
    any of them
}