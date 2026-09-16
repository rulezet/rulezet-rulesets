rule TTP_XOR_WriteProcessMemory_5ffe {
  strings:
    $key_5ffe = { 08 8c [2] 3a ae [2] 3c 9b [2] 12 9b [2] 2d 87 }

  condition:
    any of them
}