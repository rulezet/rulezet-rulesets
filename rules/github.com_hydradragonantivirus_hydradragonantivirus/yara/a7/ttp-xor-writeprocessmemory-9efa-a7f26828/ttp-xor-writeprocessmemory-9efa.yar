rule TTP_XOR_WriteProcessMemory_9efa {
  strings:
    $key_9efa = { c9 88 [2] fb aa [2] fd 9f [2] d3 9f [2] ec 83 }

  condition:
    any of them
}