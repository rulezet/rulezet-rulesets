rule TTP_XOR_WriteProcessMemory_240a {
  strings:
    $key_240a = { 73 78 [2] 41 5a [2] 47 6f [2] 69 6f [2] 56 73 }

  condition:
    any of them
}