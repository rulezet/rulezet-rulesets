rule TTP_XOR_WriteProcessMemory_2c3f {
  strings:
    $key_2c3f = { 7b 4d [2] 49 6f [2] 4f 5a [2] 61 5a [2] 5e 46 }

  condition:
    any of them
}