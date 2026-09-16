rule TTP_XOR_WriteProcessMemory_5269 {
  strings:
    $key_5269 = { 05 1b [2] 37 39 [2] 31 0c [2] 1f 0c [2] 20 10 }

  condition:
    any of them
}