rule TTP_XOR_WriteProcessMemory_9ec0 {
  strings:
    $key_9ec0 = { c9 b2 [2] fb 90 [2] fd a5 [2] d3 a5 [2] ec b9 }

  condition:
    any of them
}