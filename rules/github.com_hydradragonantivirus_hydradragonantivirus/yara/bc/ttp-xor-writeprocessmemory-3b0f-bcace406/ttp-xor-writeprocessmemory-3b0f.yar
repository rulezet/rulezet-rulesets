rule TTP_XOR_WriteProcessMemory_3b0f {
  strings:
    $key_3b0f = { 6c 7d [2] 5e 5f [2] 58 6a [2] 76 6a [2] 49 76 }

  condition:
    any of them
}