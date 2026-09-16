rule TTP_XOR_WriteProcessMemory_0138 {
  strings:
    $key_0138 = { 56 4a [2] 64 68 [2] 62 5d [2] 4c 5d [2] 73 41 }

  condition:
    any of them
}