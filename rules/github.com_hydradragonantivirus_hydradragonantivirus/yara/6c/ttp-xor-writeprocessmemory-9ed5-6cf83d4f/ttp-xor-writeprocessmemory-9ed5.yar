rule TTP_XOR_WriteProcessMemory_9ed5 {
  strings:
    $key_9ed5 = { c9 a7 [2] fb 85 [2] fd b0 [2] d3 b0 [2] ec ac }

  condition:
    any of them
}