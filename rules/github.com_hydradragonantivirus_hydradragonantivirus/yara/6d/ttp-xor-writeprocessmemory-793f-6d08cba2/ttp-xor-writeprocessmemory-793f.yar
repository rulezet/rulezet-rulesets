rule TTP_XOR_WriteProcessMemory_793f {
  strings:
    $key_793f = { 2e 4d [2] 1c 6f [2] 1a 5a [2] 34 5a [2] 0b 46 }

  condition:
    any of them
}