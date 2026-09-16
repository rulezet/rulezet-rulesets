rule TTP_XOR_WriteProcessMemory_3228 {
  strings:
    $key_3228 = { 65 5a [2] 57 78 [2] 51 4d [2] 7f 4d [2] 40 51 }

  condition:
    any of them
}