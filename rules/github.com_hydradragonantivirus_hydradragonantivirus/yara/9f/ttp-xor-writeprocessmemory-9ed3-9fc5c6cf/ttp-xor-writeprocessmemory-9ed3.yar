rule TTP_XOR_WriteProcessMemory_9ed3 {
  strings:
    $key_9ed3 = { c9 a1 [2] fb 83 [2] fd b6 [2] d3 b6 [2] ec aa }

  condition:
    any of them
}