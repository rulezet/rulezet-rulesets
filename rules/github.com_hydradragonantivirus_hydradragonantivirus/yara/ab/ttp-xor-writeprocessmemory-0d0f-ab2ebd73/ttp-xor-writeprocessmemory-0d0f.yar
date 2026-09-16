rule TTP_XOR_WriteProcessMemory_0d0f {
  strings:
    $key_0d0f = { 5a 7d [2] 68 5f [2] 6e 6a [2] 40 6a [2] 7f 76 }

  condition:
    any of them
}