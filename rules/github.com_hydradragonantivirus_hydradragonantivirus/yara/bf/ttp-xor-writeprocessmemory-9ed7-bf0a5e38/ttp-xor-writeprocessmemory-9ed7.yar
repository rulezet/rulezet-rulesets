rule TTP_XOR_WriteProcessMemory_9ed7 {
  strings:
    $key_9ed7 = { c9 a5 [2] fb 87 [2] fd b2 [2] d3 b2 [2] ec ae }

  condition:
    any of them
}