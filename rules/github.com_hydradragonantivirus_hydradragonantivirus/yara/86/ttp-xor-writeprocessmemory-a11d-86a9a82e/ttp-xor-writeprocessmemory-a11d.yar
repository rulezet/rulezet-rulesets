rule TTP_XOR_WriteProcessMemory_a11d {
  strings:
    $key_a11d = { f6 6f [2] c4 4d [2] c2 78 [2] ec 78 [2] d3 64 }

  condition:
    any of them
}