rule TTP_XOR_WriteProcessMemory_db4f {
  strings:
    $key_db4f = { 8c 3d [2] be 1f [2] b8 2a [2] 96 2a [2] a9 36 }

  condition:
    any of them
}