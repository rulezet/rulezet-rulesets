rule TTP_XOR_WriteProcessMemory_e40c {
  strings:
    $key_e40c = { b3 7e [2] 81 5c [2] 87 69 [2] a9 69 [2] 96 75 }

  condition:
    any of them
}