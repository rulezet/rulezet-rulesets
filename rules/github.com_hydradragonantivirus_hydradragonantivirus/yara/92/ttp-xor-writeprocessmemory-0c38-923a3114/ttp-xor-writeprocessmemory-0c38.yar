rule TTP_XOR_WriteProcessMemory_0c38 {
  strings:
    $key_0c38 = { 5b 4a [2] 69 68 [2] 6f 5d [2] 41 5d [2] 7e 41 }

  condition:
    any of them
}