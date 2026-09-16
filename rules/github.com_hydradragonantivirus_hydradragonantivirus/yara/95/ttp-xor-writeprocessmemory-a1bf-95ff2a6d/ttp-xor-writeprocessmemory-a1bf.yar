rule TTP_XOR_WriteProcessMemory_a1bf {
  strings:
    $key_a1bf = { f6 cd [2] c4 ef [2] c2 da [2] ec da [2] d3 c6 }

  condition:
    any of them
}