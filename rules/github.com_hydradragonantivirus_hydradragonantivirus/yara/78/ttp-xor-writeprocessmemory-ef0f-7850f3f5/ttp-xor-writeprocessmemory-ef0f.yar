rule TTP_XOR_WriteProcessMemory_ef0f {
  strings:
    $key_ef0f = { b8 7d [2] 8a 5f [2] 8c 6a [2] a2 6a [2] 9d 76 }

  condition:
    any of them
}