rule TTP_XOR_WriteProcessMemory_0ce8 {
  strings:
    $key_0ce8 = { 5b 9a [2] 69 b8 [2] 6f 8d [2] 41 8d [2] 7e 91 }

  condition:
    any of them
}