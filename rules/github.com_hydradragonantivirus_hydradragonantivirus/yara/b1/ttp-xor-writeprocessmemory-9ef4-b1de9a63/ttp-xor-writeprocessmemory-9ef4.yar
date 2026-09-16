rule TTP_XOR_WriteProcessMemory_9ef4 {
  strings:
    $key_9ef4 = { c9 86 [2] fb a4 [2] fd 91 [2] d3 91 [2] ec 8d }

  condition:
    any of them
}