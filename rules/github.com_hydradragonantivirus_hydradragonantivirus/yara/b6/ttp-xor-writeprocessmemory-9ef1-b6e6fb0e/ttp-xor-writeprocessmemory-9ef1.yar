rule TTP_XOR_WriteProcessMemory_9ef1 {
  strings:
    $key_9ef1 = { c9 83 [2] fb a1 [2] fd 94 [2] d3 94 [2] ec 88 }

  condition:
    any of them
}