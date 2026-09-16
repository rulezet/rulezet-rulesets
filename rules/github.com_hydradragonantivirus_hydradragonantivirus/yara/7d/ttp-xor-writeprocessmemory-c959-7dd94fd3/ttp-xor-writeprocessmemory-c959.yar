rule TTP_XOR_WriteProcessMemory_c959 {
  strings:
    $key_c959 = { 9e 2b [2] ac 09 [2] aa 3c [2] 84 3c [2] bb 20 }

  condition:
    any of them
}