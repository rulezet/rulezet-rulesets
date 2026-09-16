rule TTP_XOR_QUAD_CurrentVersionRun_cb81 {
  strings:
    $key_cb81 = { 98 ee [2] bc e0 [2] 97 cc [2] b9 ee [2] ad f5 [2] a2 ef [2] bc f2 [2] be f3 [2] a5 f5 [2] b9 f2 [2] a5 dd }

  condition:
    any of them
}