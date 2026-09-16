rule TTP_XOR_WriteProcessMemory_9f8c {
  strings:
    $key_9f8c = { c8 fe [2] fa dc [2] fc e9 [2] d2 e9 [2] ed f5 }

  condition:
    any of them
}