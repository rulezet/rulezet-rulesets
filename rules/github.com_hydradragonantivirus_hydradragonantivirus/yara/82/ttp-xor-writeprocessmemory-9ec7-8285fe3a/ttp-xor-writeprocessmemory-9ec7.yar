rule TTP_XOR_WriteProcessMemory_9ec7 {
  strings:
    $key_9ec7 = { c9 b5 [2] fb 97 [2] fd a2 [2] d3 a2 [2] ec be }

  condition:
    any of them
}