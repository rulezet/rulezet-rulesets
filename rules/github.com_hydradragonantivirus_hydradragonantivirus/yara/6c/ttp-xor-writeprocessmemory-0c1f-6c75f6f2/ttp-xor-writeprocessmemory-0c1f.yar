rule TTP_XOR_WriteProcessMemory_0c1f {
  strings:
    $key_0c1f = { 5b 6d [2] 69 4f [2] 6f 7a [2] 41 7a [2] 7e 66 }

  condition:
    any of them
}