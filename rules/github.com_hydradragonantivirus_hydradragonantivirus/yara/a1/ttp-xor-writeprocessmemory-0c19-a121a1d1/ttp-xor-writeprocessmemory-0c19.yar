rule TTP_XOR_WriteProcessMemory_0c19 {
  strings:
    $key_0c19 = { 5b 6b [2] 69 49 [2] 6f 7c [2] 41 7c [2] 7e 60 }

  condition:
    any of them
}