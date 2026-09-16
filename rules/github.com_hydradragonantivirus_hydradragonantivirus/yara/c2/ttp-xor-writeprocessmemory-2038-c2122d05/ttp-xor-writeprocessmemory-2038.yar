rule TTP_XOR_WriteProcessMemory_2038 {
  strings:
    $key_2038 = { 77 4a [2] 45 68 [2] 43 5d [2] 6d 5d [2] 52 41 }

  condition:
    any of them
}