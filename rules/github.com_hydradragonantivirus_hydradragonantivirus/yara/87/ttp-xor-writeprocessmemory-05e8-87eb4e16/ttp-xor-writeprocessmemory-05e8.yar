rule TTP_XOR_WriteProcessMemory_05e8 {
  strings:
    $key_05e8 = { 52 9a [2] 60 b8 [2] 66 8d [2] 48 8d [2] 77 91 }

  condition:
    any of them
}