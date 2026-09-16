rule TTP_XOR_WriteProcessMemory_7a19 {
  strings:
    $key_7a19 = { 2d 6b [2] 1f 49 [2] 19 7c [2] 37 7c [2] 08 60 }

  condition:
    any of them
}