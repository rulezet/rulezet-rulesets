rule TTP_XOR_WriteProcessMemory_2c38 {
  strings:
    $key_2c38 = { 7b 4a [2] 49 68 [2] 4f 5d [2] 61 5d [2] 5e 41 }

  condition:
    any of them
}