rule TTP_XOR_WriteProcessMemory_9ec4 {
  strings:
    $key_9ec4 = { c9 b6 [2] fb 94 [2] fd a1 [2] d3 a1 [2] ec bd }

  condition:
    any of them
}