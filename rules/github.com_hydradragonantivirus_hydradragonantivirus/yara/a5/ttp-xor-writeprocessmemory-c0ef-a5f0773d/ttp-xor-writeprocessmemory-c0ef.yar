rule TTP_XOR_WriteProcessMemory_c0ef {
  strings:
    $key_c0ef = { 97 9d [2] a5 bf [2] a3 8a [2] 8d 8a [2] b2 96 }

  condition:
    any of them
}