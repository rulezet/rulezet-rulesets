rule TTP_XOR_WriteProcessMemory_9eca {
  strings:
    $key_9eca = { c9 b8 [2] fb 9a [2] fd af [2] d3 af [2] ec b3 }

  condition:
    any of them
}