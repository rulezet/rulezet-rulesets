rule TTP_XOR_WriteProcessMemory_0828 {
  strings:
    $key_0828 = { 5f 5a [2] 6d 78 [2] 6b 4d [2] 45 4d [2] 7a 51 }

  condition:
    any of them
}