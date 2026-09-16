rule TTP_XOR_WriteProcessMemory_010a {
  strings:
    $key_010a = { 56 78 [2] 64 5a [2] 62 6f [2] 4c 6f [2] 73 73 }

  condition:
    any of them
}