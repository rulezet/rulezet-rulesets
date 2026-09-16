rule TTP_XOR_WriteProcessMemory_edc3 {
  strings:
    $key_edc3 = { ba b1 [2] 88 93 [2] 8e a6 [2] a0 a6 [2] 9f ba }

  condition:
    any of them
}