rule TTP_XOR_WriteProcessMemory_653f {
  strings:
    $key_653f = { 32 4d [2] 00 6f [2] 06 5a [2] 28 5a [2] 17 46 }

  condition:
    any of them
}