rule TTP_XOR_WriteProcessMemory_d40d {
  strings:
    $key_d40d = { 83 7f [2] b1 5d [2] b7 68 [2] 99 68 [2] a6 74 }

  condition:
    any of them
}