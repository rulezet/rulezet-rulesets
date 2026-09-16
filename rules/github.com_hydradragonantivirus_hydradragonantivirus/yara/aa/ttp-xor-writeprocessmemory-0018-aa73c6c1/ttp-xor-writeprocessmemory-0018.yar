rule TTP_XOR_WriteProcessMemory_0018 {
  strings:
    $key_0018 = { 57 6a [2] 65 48 [2] 63 7d [2] 4d 7d [2] 72 61 }

  condition:
    any of them
}