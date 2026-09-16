rule TTP_XOR_WriteProcessMemory_e32c {
  strings:
    $key_e32c = { b4 5e [2] 86 7c [2] 80 49 [2] ae 49 [2] 91 55 }

  condition:
    any of them
}