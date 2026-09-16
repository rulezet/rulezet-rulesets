rule TTP_XOR_WriteProcessMemory_733f {
  strings:
    $key_733f = { 24 4d [2] 16 6f [2] 10 5a [2] 3e 5a [2] 01 46 }

  condition:
    any of them
}