rule TTP_XOR_WriteProcessMemory_1ffe {
  strings:
    $key_1ffe = { 48 8c [2] 7a ae [2] 7c 9b [2] 52 9b [2] 6d 87 }

  condition:
    any of them
}