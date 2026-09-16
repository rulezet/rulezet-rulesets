rule TTP_XOR_WriteProcessMemory_df4f {
  strings:
    $key_df4f = { 88 3d [2] ba 1f [2] bc 2a [2] 92 2a [2] ad 36 }

  condition:
    any of them
}