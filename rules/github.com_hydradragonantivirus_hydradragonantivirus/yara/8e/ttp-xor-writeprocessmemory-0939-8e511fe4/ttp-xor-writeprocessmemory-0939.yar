rule TTP_XOR_WriteProcessMemory_0939 {
  strings:
    $key_0939 = { 5e 4b [2] 6c 69 [2] 6a 5c [2] 44 5c [2] 7b 40 }

  condition:
    any of them
}