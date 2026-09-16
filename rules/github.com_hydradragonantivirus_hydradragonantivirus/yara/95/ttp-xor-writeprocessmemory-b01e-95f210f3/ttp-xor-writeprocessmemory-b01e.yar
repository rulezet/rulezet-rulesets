rule TTP_XOR_WriteProcessMemory_b01e {
  strings:
    $key_b01e = { e7 6c [2] d5 4e [2] d3 7b [2] fd 7b [2] c2 67 }

  condition:
    any of them
}