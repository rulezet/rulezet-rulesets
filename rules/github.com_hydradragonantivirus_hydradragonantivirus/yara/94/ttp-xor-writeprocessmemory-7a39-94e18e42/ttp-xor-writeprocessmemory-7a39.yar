rule TTP_XOR_WriteProcessMemory_7a39 {
  strings:
    $key_7a39 = { 2d 4b [2] 1f 69 [2] 19 5c [2] 37 5c [2] 08 40 }

  condition:
    any of them
}