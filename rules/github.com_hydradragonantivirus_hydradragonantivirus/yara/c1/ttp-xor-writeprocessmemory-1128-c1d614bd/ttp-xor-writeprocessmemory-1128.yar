rule TTP_XOR_WriteProcessMemory_1128 {
  strings:
    $key_1128 = { 46 5a [2] 74 78 [2] 72 4d [2] 5c 4d [2] 63 51 }

  condition:
    any of them
}