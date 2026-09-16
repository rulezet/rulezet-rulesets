rule TTP_XOR_WriteProcessMemory_2b0f {
  strings:
    $key_2b0f = { 7c 7d [2] 4e 5f [2] 48 6a [2] 66 6a [2] 59 76 }

  condition:
    any of them
}