rule TTP_XOR_WriteProcessMemory_53ca {
  strings:
    $key_53ca = { 04 b8 [2] 36 9a [2] 30 af [2] 1e af [2] 21 b3 }

  condition:
    any of them
}