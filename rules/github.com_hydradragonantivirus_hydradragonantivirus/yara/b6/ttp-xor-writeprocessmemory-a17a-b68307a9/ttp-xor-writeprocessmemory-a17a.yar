rule TTP_XOR_WriteProcessMemory_a17a {
  strings:
    $key_a17a = { f6 08 [2] c4 2a [2] c2 1f [2] ec 1f [2] d3 03 }

  condition:
    any of them
}