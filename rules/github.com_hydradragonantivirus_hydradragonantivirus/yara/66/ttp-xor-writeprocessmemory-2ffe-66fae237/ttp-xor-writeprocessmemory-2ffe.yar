rule TTP_XOR_WriteProcessMemory_2ffe {
  strings:
    $key_2ffe = { 78 8c [2] 4a ae [2] 4c 9b [2] 62 9b [2] 5d 87 }

  condition:
    any of them
}