rule TTP_XOR_WriteProcessMemory_3dff {
  strings:
    $key_3dff = { 6a 8d [2] 58 af [2] 5e 9a [2] 70 9a [2] 4f 86 }

  condition:
    any of them
}