rule TTP_XOR_WriteProcessMemory_a1fa {
  strings:
    $key_a1fa = { f6 88 [2] c4 aa [2] c2 9f [2] ec 9f [2] d3 83 }

  condition:
    any of them
}