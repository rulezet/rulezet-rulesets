rule TTP_XOR_WriteProcessMemory_e539 {
  strings:
    $key_e539 = { b2 4b [2] 80 69 [2] 86 5c [2] a8 5c [2] 97 40 }

  condition:
    any of them
}