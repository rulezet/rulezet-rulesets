rule TTP_XOR_WriteProcessMemory_4469 {
  strings:
    $key_4469 = { 13 1b [2] 21 39 [2] 27 0c [2] 09 0c [2] 36 10 }

  condition:
    any of them
}