rule TTP_XOR_QUAD_CurrentVersionRun_8aa9 {
  strings:
    $key_8aa9 = { d9 c6 [2] fd c8 [2] d6 e4 [2] f8 c6 [2] ec dd [2] e3 c7 [2] fd da [2] ff db [2] e4 dd [2] f8 da [2] e4 f5 }

  condition:
    any of them
}