rule TTP_XOR_QUAD_CurrentVersionRun_aaf0 {
  strings:
    $key_aaf0 = { f9 9f [2] dd 91 [2] f6 bd [2] d8 9f [2] cc 84 [2] c3 9e [2] dd 83 [2] df 82 [2] c4 84 [2] d8 83 [2] c4 ac }

  condition:
    any of them
}