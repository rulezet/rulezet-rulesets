rule TTP_XOR_WriteProcessMemory_acbe {
  strings:
    $key_acbe = { fb cc [2] c9 ee [2] cf db [2] e1 db [2] de c7 }

  condition:
    any of them
}