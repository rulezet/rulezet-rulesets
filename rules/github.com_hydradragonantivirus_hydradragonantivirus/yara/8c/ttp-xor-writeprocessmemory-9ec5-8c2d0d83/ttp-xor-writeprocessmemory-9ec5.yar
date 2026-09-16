rule TTP_XOR_WriteProcessMemory_9ec5 {
  strings:
    $key_9ec5 = { c9 b7 [2] fb 95 [2] fd a0 [2] d3 a0 [2] ec bc }

  condition:
    any of them
}