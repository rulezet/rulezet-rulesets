rule TTP_XOR_WriteProcessMemory_31e8 {
  strings:
    $key_31e8 = { 66 9a [2] 54 b8 [2] 52 8d [2] 7c 8d [2] 43 91 }

  condition:
    any of them
}