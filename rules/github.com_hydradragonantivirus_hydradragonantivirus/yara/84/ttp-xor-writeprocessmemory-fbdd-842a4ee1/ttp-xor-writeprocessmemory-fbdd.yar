rule TTP_XOR_WriteProcessMemory_fbdd {
  strings:
    $key_fbdd = { ac af [2] 9e 8d [2] 98 b8 [2] b6 b8 [2] 89 a4 }

  condition:
    any of them
}