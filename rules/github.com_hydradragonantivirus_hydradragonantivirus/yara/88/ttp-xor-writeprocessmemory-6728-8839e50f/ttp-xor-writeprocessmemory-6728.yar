rule TTP_XOR_WriteProcessMemory_6728 {
  strings:
    $key_6728 = { 30 5a [2] 02 78 [2] 04 4d [2] 2a 4d [2] 15 51 }

  condition:
    any of them
}