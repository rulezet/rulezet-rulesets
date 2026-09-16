rule TTP_XOR_WriteProcessMemory_faff {
  strings:
    $key_faff = { ad 8d [2] 9f af [2] 99 9a [2] b7 9a [2] 88 86 }

  condition:
    any of them
}