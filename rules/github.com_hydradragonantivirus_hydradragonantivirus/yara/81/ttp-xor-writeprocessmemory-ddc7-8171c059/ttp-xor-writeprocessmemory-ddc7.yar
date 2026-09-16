rule TTP_XOR_WriteProcessMemory_ddc7 {
  strings:
    $key_ddc7 = { 8a b5 [2] b8 97 [2] be a2 [2] 90 a2 [2] af be }

  condition:
    any of them
}