rule TTP_XOR_WriteProcessMemory_6029 {
  strings:
    $key_6029 = { 37 5b [2] 05 79 [2] 03 4c [2] 2d 4c [2] 12 50 }

  condition:
    any of them
}