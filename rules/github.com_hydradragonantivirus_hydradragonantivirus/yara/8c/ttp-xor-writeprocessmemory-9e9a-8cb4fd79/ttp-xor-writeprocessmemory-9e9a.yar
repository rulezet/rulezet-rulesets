rule TTP_XOR_WriteProcessMemory_9e9a {
  strings:
    $key_9e9a = { c9 e8 [2] fb ca [2] fd ff [2] d3 ff [2] ec e3 }

  condition:
    any of them
}