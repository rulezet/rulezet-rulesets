rule TTP_XOR_WriteProcessMemory_bdc3 {
  strings:
    $key_bdc3 = { ea b1 [2] d8 93 [2] de a6 [2] f0 a6 [2] cf ba }

  condition:
    any of them
}