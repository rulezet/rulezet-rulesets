rule TTP_XOR_WriteProcessMemory_0c59 {
  strings:
    $key_0c59 = { 5b 2b [2] 69 09 [2] 6f 3c [2] 41 3c [2] 7e 20 }

  condition:
    any of them
}