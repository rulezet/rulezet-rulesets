rule TTP_XOR_WriteProcessMemory_3218 {
  strings:
    $key_3218 = { 65 6a [2] 57 48 [2] 51 7d [2] 7f 7d [2] 40 61 }

  condition:
    any of them
}