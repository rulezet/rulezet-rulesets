rule TTP_XOR_WriteProcessMemory_3f69 {
  strings:
    $key_3f69 = { 68 1b [2] 5a 39 [2] 5c 0c [2] 72 0c [2] 4d 10 }

  condition:
    any of them
}