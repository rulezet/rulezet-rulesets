rule TTP_XOR_WriteProcessMemory_f89c {
  strings:
    $key_f89c = { af ee [2] 9d cc [2] 9b f9 [2] b5 f9 [2] 8a e5 }

  condition:
    any of them
}