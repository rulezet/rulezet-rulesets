rule TTP_XOR_WriteProcessMemory_3ce8 {
  strings:
    $key_3ce8 = { 6b 9a [2] 59 b8 [2] 5f 8d [2] 71 8d [2] 4e 91 }

  condition:
    any of them
}