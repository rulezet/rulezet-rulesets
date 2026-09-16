rule TTP_XOR_WriteProcessMemory_abc3 {
  strings:
    $key_abc3 = { fc b1 [2] ce 93 [2] c8 a6 [2] e6 a6 [2] d9 ba }

  condition:
    any of them
}