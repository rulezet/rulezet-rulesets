rule TTP_XOR_WriteProcessMemory_ee29 {
  strings:
    $key_ee29 = { b9 5b [2] 8b 79 [2] 8d 4c [2] a3 4c [2] 9c 50 }

  condition:
    any of them
}