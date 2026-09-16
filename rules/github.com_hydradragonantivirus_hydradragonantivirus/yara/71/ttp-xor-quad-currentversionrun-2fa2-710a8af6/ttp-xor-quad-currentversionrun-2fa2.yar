rule TTP_XOR_QUAD_CurrentVersionRun_2fa2 {
  strings:
    $key_2fa2 = { 7c cd [2] 58 c3 [2] 73 ef [2] 5d cd [2] 49 d6 [2] 46 cc [2] 58 d1 [2] 5a d0 [2] 41 d6 [2] 5d d1 [2] 41 fe }

  condition:
    any of them
}