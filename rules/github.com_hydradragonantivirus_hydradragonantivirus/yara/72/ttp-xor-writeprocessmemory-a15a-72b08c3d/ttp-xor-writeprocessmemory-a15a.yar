rule TTP_XOR_WriteProcessMemory_a15a {
  strings:
    $key_a15a = { f6 28 [2] c4 0a [2] c2 3f [2] ec 3f [2] d3 23 }

  condition:
    any of them
}