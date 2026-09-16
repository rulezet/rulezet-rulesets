rule TTP_XOR_WriteProcessMemory_a13c {
  strings:
    $key_a13c = { f6 4e [2] c4 6c [2] c2 59 [2] ec 59 [2] d3 45 }

  condition:
    any of them
}