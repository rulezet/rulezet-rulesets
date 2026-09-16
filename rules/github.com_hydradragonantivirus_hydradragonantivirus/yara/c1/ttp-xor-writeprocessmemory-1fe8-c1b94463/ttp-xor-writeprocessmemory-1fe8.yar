rule TTP_XOR_WriteProcessMemory_1fe8 {
  strings:
    $key_1fe8 = { 48 9a [2] 7a b8 [2] 7c 8d [2] 52 8d [2] 6d 91 }

  condition:
    any of them
}