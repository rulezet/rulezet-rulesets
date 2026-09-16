rule TTP_XOR_WriteProcessMemory_3d3e {
  strings:
    $key_3d3e = { 6a 4c [2] 58 6e [2] 5e 5b [2] 70 5b [2] 4f 47 }

  condition:
    any of them
}