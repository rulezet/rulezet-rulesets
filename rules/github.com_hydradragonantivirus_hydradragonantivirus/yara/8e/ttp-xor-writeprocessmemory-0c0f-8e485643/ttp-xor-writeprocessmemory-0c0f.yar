rule TTP_XOR_WriteProcessMemory_0c0f {
  strings:
    $key_0c0f = { 5b 7d [2] 69 5f [2] 6f 6a [2] 41 6a [2] 7e 76 }

  condition:
    any of them
}