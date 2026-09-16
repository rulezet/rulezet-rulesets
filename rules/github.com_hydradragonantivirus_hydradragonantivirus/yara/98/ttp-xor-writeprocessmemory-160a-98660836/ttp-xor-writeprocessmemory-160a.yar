rule TTP_XOR_WriteProcessMemory_160a {
  strings:
    $key_160a = { 41 78 [2] 73 5a [2] 75 6f [2] 5b 6f [2] 64 73 }

  condition:
    any of them
}