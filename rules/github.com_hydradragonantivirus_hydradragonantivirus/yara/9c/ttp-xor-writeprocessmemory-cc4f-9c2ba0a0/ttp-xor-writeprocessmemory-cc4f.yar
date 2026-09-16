rule TTP_XOR_WriteProcessMemory_cc4f {
  strings:
    $key_cc4f = { 9b 3d [2] a9 1f [2] af 2a [2] 81 2a [2] be 36 }

  condition:
    any of them
}