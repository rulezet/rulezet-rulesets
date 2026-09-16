rule TTP_XOR_WriteProcessMemory_a1f4 {
  strings:
    $key_a1f4 = { f6 86 [2] c4 a4 [2] c2 91 [2] ec 91 [2] d3 8d }

  condition:
    any of them
}