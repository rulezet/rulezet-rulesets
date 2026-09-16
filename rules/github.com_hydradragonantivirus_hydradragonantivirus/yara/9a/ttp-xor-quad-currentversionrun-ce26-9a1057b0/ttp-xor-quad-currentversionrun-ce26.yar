rule TTP_XOR_QUAD_CurrentVersionRun_ce26 {
  strings:
    $key_ce26 = { 9d 49 [2] b9 47 [2] 92 6b [2] bc 49 [2] a8 52 [2] a7 48 [2] b9 55 [2] bb 54 [2] a0 52 [2] bc 55 [2] a0 7a }

  condition:
    any of them
}