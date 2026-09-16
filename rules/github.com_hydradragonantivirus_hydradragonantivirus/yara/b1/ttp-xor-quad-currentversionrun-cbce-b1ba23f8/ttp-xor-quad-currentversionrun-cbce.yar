rule TTP_XOR_QUAD_CurrentVersionRun_cbce {
  strings:
    $key_cbce = { 98 a1 [2] bc af [2] 97 83 [2] b9 a1 [2] ad ba [2] a2 a0 [2] bc bd [2] be bc [2] a5 ba [2] b9 bd [2] a5 92 }

  condition:
    any of them
}