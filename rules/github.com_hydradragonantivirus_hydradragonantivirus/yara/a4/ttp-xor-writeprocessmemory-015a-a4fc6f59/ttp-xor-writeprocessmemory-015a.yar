rule TTP_XOR_WriteProcessMemory_015a {
  strings:
    $key_015a = { 56 28 [2] 64 0a [2] 62 3f [2] 4c 3f [2] 73 23 }

  condition:
    any of them
}