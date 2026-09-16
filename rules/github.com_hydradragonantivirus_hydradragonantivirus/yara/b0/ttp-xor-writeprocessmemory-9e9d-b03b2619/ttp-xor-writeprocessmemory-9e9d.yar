rule TTP_XOR_WriteProcessMemory_9e9d {
  strings:
    $key_9e9d = { c9 ef [2] fb cd [2] fd f8 [2] d3 f8 [2] ec e4 }

  condition:
    any of them
}