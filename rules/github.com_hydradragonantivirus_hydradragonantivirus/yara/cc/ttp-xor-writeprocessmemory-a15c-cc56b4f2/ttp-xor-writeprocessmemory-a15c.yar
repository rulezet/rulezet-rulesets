rule TTP_XOR_WriteProcessMemory_a15c {
  strings:
    $key_a15c = { f6 2e [2] c4 0c [2] c2 39 [2] ec 39 [2] d3 25 }

  condition:
    any of them
}