rule TTP_XOR_WriteProcessMemory_24e8 {
  strings:
    $key_24e8 = { 73 9a [2] 41 b8 [2] 47 8d [2] 69 8d [2] 56 91 }

  condition:
    any of them
}