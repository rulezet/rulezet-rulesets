rule TTP_XOR_WriteProcessMemory_ca39 {
  strings:
    $key_ca39 = { 9d 4b [2] af 69 [2] a9 5c [2] 87 5c [2] b8 40 }

  condition:
    any of them
}