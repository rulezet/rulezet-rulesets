rule TTP_XOR_WriteProcessMemory_4ffe {
  strings:
    $key_4ffe = { 18 8c [2] 2a ae [2] 2c 9b [2] 02 9b [2] 3d 87 }

  condition:
    any of them
}