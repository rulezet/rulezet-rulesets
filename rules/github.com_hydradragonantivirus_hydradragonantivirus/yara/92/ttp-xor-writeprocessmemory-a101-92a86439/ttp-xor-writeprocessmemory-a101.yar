rule TTP_XOR_WriteProcessMemory_a101 {
  strings:
    $key_a101 = { f6 73 [2] c4 51 [2] c2 64 [2] ec 64 [2] d3 78 }

  condition:
    any of them
}