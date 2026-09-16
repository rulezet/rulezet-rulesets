rule TTP_XOR_WriteProcessMemory_136e {
  strings:
    $key_136e = { 44 1c [2] 76 3e [2] 70 0b [2] 5e 0b [2] 61 17 }

  condition:
    any of them
}