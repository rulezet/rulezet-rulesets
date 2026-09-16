rule TTP_XOR_WriteProcessMemory_9e35 {
  strings:
    $key_9e35 = { c9 47 [2] fb 65 [2] fd 50 [2] d3 50 [2] ec 4c }

  condition:
    any of them
}