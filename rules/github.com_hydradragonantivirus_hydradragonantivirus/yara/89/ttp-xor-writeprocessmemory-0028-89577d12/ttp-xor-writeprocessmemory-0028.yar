rule TTP_XOR_WriteProcessMemory_0028 {
  strings:
    $key_0028 = { 57 5a [2] 65 78 [2] 63 4d [2] 4d 4d [2] 72 51 }

  condition:
    any of them
}