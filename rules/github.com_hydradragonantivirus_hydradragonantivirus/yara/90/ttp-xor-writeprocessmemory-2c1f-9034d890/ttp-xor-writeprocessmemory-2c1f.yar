rule TTP_XOR_WriteProcessMemory_2c1f {
  strings:
    $key_2c1f = { 7b 6d [2] 49 4f [2] 4f 7a [2] 61 7a [2] 5e 66 }

  condition:
    any of them
}