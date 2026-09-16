rule TTP_XOR_WriteProcessMemory_2f69 {
  strings:
    $key_2f69 = { 78 1b [2] 4a 39 [2] 4c 0c [2] 62 0c [2] 5d 10 }

  condition:
    any of them
}