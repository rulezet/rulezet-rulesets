rule TTP_XOR_WriteProcessMemory_2128 {
  strings:
    $key_2128 = { 76 5a [2] 44 78 [2] 42 4d [2] 6c 4d [2] 53 51 }

  condition:
    any of them
}