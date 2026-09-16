rule TTP_XOR_WriteProcessMemory_fdef {
  strings:
    $key_fdef = { aa 9d [2] 98 bf [2] 9e 8a [2] b0 8a [2] 8f 96 }

  condition:
    any of them
}