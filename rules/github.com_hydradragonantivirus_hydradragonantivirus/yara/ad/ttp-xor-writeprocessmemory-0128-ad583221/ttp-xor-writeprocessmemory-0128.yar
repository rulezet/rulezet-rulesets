rule TTP_XOR_WriteProcessMemory_0128 {
  strings:
    $key_0128 = { 56 5a [2] 64 78 [2] 62 4d [2] 4c 4d [2] 73 51 }

  condition:
    any of them
}