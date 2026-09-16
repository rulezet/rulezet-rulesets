rule TTP_XOR_WriteProcessMemory_bdc7 {
  strings:
    $key_bdc7 = { ea b5 [2] d8 97 [2] de a2 [2] f0 a2 [2] cf be }

  condition:
    any of them
}