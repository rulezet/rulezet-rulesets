rule TTP_XOR_WriteProcessMemory_ef59 {
  strings:
    $key_ef59 = { b8 2b [2] 8a 09 [2] 8c 3c [2] a2 3c [2] 9d 20 }

  condition:
    any of them
}