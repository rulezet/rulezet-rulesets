rule TTP_XOR_WriteProcessMemory_abad {
  strings:
    $key_abad = { fc df [2] ce fd [2] c8 c8 [2] e6 c8 [2] d9 d4 }

  condition:
    any of them
}