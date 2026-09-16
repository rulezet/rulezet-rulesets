rule TTP_XOR_WriteProcessMemory_9ea8 {
  strings:
    $key_9ea8 = { c9 da [2] fb f8 [2] fd cd [2] d3 cd [2] ec d1 }

  condition:
    any of them
}