rule TTP_XOR_WriteProcessMemory_020f {
  strings:
    $key_020f = { 55 7d [2] 67 5f [2] 61 6a [2] 4f 6a [2] 70 76 }

  condition:
    any of them
}