rule TTP_XOR_WriteProcessMemory_a18d {
  strings:
    $key_a18d = { f6 ff [2] c4 dd [2] c2 e8 [2] ec e8 [2] d3 f4 }

  condition:
    any of them
}