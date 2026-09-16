rule TTP_XOR_WriteProcessMemory_3159 {
  strings:
    $key_3159 = { 66 2b [2] 54 09 [2] 52 3c [2] 7c 3c [2] 43 20 }

  condition:
    any of them
}