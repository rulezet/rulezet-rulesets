rule TTP_XOR_QUAD_CurrentVersionRun_cb66 {
  strings:
    $key_cb66 = { 98 09 [2] bc 07 [2] 97 2b [2] b9 09 [2] ad 12 [2] a2 08 [2] bc 15 [2] be 14 [2] a5 12 [2] b9 15 [2] a5 3a }

  condition:
    any of them
}