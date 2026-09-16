rule TTP_XOR_WriteProcessMemory_6238 {
  strings:
    $key_6238 = { 35 4a [2] 07 68 [2] 01 5d [2] 2f 5d [2] 10 41 }

  condition:
    any of them
}