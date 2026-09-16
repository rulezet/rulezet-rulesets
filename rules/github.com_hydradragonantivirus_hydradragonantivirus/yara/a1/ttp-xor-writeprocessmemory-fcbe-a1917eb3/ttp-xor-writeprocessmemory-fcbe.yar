rule TTP_XOR_WriteProcessMemory_fcbe {
  strings:
    $key_fcbe = { ab cc [2] 99 ee [2] 9f db [2] b1 db [2] 8e c7 }

  condition:
    any of them
}