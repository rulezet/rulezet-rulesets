rule TTP_XOR_WriteProcessMemory_ab32 {
  strings:
    $key_ab32 = { fc 40 [2] ce 62 [2] c8 57 [2] e6 57 [2] d9 4b }

  condition:
    any of them
}