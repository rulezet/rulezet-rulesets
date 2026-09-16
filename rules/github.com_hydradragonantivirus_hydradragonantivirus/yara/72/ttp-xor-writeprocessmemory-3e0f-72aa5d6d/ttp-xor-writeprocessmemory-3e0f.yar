rule TTP_XOR_WriteProcessMemory_3e0f {
  strings:
    $key_3e0f = { 69 7d [2] 5b 5f [2] 5d 6a [2] 73 6a [2] 4c 76 }

  condition:
    any of them
}