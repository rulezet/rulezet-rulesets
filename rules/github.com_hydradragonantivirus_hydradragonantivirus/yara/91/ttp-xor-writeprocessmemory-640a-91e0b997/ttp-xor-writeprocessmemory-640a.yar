rule TTP_XOR_WriteProcessMemory_640a {
  strings:
    $key_640a = { 33 78 [2] 01 5a [2] 07 6f [2] 29 6f [2] 16 73 }

  condition:
    any of them
}