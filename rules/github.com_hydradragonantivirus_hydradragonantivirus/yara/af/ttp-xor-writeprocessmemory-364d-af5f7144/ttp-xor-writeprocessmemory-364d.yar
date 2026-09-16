rule TTP_XOR_WriteProcessMemory_364d {
  strings:
    $key_364d = { 61 3f [2] 53 1d [2] 55 28 [2] 7b 28 [2] 44 34 }

  condition:
    any of them
}