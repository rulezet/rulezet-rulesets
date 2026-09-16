rule TTP_XOR_WriteProcessMemory_0f38 {
  strings:
    $key_0f38 = { 58 4a [2] 6a 68 [2] 6c 5d [2] 42 5d [2] 7d 41 }

  condition:
    any of them
}