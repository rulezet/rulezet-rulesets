rule TTP_XOR_WriteProcessMemory_dc39 {
  strings:
    $key_dc39 = { 8b 4b [2] b9 69 [2] bf 5c [2] 91 5c [2] ae 40 }

  condition:
    any of them
}