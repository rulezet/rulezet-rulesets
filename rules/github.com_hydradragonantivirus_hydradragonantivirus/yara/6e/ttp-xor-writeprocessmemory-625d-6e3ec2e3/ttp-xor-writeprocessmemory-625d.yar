rule TTP_XOR_WriteProcessMemory_625d {
  strings:
    $key_625d = { 35 2f [2] 07 0d [2] 01 38 [2] 2f 38 [2] 10 24 }

  condition:
    any of them
}