rule TTP_XOR_WriteProcessMemory_9ee5 {
  strings:
    $key_9ee5 = { c9 97 [2] fb b5 [2] fd 80 [2] d3 80 [2] ec 9c }

  condition:
    any of them
}