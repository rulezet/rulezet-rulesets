rule TTP_XOR_WriteProcessMemory_0ffe {
  strings:
    $key_0ffe = { 58 8c [2] 6a ae [2] 6c 9b [2] 42 9b [2] 7d 87 }

  condition:
    any of them
}