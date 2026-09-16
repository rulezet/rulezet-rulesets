rule TTP_XOR_WriteProcessMemory_0c3f {
  strings:
    $key_0c3f = { 5b 4d [2] 69 6f [2] 6f 5a [2] 41 5a [2] 7e 46 }

  condition:
    any of them
}