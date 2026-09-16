rule TTP_XOR_WriteProcessMemory_ee59 {
  strings:
    $key_ee59 = { b9 2b [2] 8b 09 [2] 8d 3c [2] a3 3c [2] 9c 20 }

  condition:
    any of them
}