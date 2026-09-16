rule TTP_XOR_WriteProcessMemory_0f2f {
  strings:
    $key_0f2f = { 58 5d [2] 6a 7f [2] 6c 4a [2] 42 4a [2] 7d 56 }

  condition:
    any of them
}