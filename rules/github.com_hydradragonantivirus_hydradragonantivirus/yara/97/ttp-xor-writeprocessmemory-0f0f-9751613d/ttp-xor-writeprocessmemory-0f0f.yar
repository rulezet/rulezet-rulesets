rule TTP_XOR_WriteProcessMemory_0f0f {
  strings:
    $key_0f0f = { 58 7d [2] 6a 5f [2] 6c 6a [2] 42 6a [2] 7d 76 }

  condition:
    any of them
}