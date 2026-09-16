rule TTP_XOR_WriteProcessMemory_e40d {
  strings:
    $key_e40d = { b3 7f [2] 81 5d [2] 87 68 [2] a9 68 [2] 96 74 }

  condition:
    any of them
}