rule TTP_XOR_WriteProcessMemory_bdc6 {
  strings:
    $key_bdc6 = { ea b4 [2] d8 96 [2] de a3 [2] f0 a3 [2] cf bf }

  condition:
    any of them
}