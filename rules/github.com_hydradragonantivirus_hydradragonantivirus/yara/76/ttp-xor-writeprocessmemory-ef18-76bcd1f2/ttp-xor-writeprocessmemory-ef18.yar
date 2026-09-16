rule TTP_XOR_WriteProcessMemory_ef18 {
  strings:
    $key_ef18 = { b8 6a [2] 8a 48 [2] 8c 7d [2] a2 7d [2] 9d 61 }

  condition:
    any of them
}