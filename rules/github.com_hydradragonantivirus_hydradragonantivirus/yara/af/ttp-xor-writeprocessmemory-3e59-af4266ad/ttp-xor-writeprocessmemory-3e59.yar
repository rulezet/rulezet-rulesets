rule TTP_XOR_WriteProcessMemory_3e59 {
  strings:
    $key_3e59 = { 69 2b [2] 5b 09 [2] 5d 3c [2] 73 3c [2] 4c 20 }

  condition:
    any of them
}