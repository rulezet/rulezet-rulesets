rule TTP_XOR_WriteProcessMemory_acb5 {
  strings:
    $key_acb5 = { fb c7 [2] c9 e5 [2] cf d0 [2] e1 d0 [2] de cc }

  condition:
    any of them
}