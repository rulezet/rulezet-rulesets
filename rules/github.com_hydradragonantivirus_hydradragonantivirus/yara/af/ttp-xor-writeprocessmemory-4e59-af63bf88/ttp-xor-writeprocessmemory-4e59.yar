rule TTP_XOR_WriteProcessMemory_4e59 {
  strings:
    $key_4e59 = { 19 2b [2] 2b 09 [2] 2d 3c [2] 03 3c [2] 3c 20 }

  condition:
    any of them
}