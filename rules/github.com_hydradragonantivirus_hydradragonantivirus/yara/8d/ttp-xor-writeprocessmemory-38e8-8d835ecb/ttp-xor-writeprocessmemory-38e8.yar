rule TTP_XOR_WriteProcessMemory_38e8 {
  strings:
    $key_38e8 = { 6f 9a [2] 5d b8 [2] 5b 8d [2] 75 8d [2] 4a 91 }

  condition:
    any of them
}