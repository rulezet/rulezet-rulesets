rule TTP_XOR_WriteProcessMemory_0a0f {
  strings:
    $key_0a0f = { 5d 7d [2] 6f 5f [2] 69 6a [2] 47 6a [2] 78 76 }

  condition:
    any of them
}