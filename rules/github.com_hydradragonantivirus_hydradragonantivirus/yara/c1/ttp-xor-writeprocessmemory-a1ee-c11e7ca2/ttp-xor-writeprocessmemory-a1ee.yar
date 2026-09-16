rule TTP_XOR_WriteProcessMemory_a1ee {
  strings:
    $key_a1ee = { f6 9c [2] c4 be [2] c2 8b [2] ec 8b [2] d3 97 }

  condition:
    any of them
}