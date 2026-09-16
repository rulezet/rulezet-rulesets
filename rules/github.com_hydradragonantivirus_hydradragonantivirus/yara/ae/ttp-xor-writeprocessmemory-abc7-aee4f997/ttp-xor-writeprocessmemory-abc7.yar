rule TTP_XOR_WriteProcessMemory_abc7 {
  strings:
    $key_abc7 = { fc b5 [2] ce 97 [2] c8 a2 [2] e6 a2 [2] d9 be }

  condition:
    any of them
}