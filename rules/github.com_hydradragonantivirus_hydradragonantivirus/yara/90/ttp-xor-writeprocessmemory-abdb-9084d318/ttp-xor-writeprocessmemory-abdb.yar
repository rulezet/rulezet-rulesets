rule TTP_XOR_WriteProcessMemory_abdb {
  strings:
    $key_abdb = { fc a9 [2] ce 8b [2] c8 be [2] e6 be [2] d9 a2 }

  condition:
    any of them
}