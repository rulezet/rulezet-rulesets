rule TTP_XOR_WriteProcessMemory_2a0a {
  strings:
    $key_2a0a = { 7d 78 [2] 4f 5a [2] 49 6f [2] 67 6f [2] 58 73 }

  condition:
    any of them
}