rule TTP_XOR_WriteProcessMemory_a3db {
  strings:
    $key_a3db = { f4 a9 [2] c6 8b [2] c0 be [2] ee be [2] d1 a2 }

  condition:
    any of them
}