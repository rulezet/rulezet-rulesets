rule TTP_XOR_WriteProcessMemory_6269 {
  strings:
    $key_6269 = { 35 1b [2] 07 39 [2] 01 0c [2] 2f 0c [2] 10 10 }

  condition:
    any of them
}