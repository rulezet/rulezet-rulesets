rule TTP_XOR_WriteProcessMemory_620a {
  strings:
    $key_620a = { 35 78 [2] 07 5a [2] 01 6f [2] 2f 6f [2] 10 73 }

  condition:
    any of them
}