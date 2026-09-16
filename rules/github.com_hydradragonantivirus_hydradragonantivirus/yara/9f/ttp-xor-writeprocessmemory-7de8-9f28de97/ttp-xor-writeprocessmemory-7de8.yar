rule TTP_XOR_WriteProcessMemory_7de8 {
  strings:
    $key_7de8 = { 2a 9a [2] 18 b8 [2] 1e 8d [2] 30 8d [2] 0f 91 }

  condition:
    any of them
}