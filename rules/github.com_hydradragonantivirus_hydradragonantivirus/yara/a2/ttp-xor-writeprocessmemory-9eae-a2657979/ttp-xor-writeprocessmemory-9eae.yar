rule TTP_XOR_WriteProcessMemory_9eae {
  strings:
    $key_9eae = { c9 dc [2] fb fe [2] fd cb [2] d3 cb [2] ec d7 }

  condition:
    any of them
}