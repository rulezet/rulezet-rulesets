rule TTP_XOR_WriteProcessMemory_021d {
  strings:
    $key_021d = { 55 6f [2] 67 4d [2] 61 78 [2] 4f 78 [2] 70 64 }

  condition:
    any of them
}