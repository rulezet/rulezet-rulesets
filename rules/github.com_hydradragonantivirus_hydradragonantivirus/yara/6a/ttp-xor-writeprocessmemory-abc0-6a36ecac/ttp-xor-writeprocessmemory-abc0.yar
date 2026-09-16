rule TTP_XOR_WriteProcessMemory_abc0 {
  strings:
    $key_abc0 = { fc b2 [2] ce 90 [2] c8 a5 [2] e6 a5 [2] d9 b9 }

  condition:
    any of them
}