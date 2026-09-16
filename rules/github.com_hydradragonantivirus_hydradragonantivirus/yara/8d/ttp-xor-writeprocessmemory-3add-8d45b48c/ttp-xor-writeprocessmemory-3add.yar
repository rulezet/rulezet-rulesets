rule TTP_XOR_WriteProcessMemory_3add {
  strings:
    $key_3add = { 6d af [2] 5f 8d [2] 59 b8 [2] 77 b8 [2] 48 a4 }

  condition:
    any of them
}