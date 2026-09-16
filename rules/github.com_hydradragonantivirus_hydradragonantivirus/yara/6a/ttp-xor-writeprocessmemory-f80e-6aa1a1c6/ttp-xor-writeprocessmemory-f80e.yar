rule TTP_XOR_WriteProcessMemory_f80e {
  strings:
    $key_f80e = { af 7c [2] 9d 5e [2] 9b 6b [2] b5 6b [2] 8a 77 }

  condition:
    any of them
}