rule TTP_XOR_QUAD_CurrentVersionRun_cbfb {
  strings:
    $key_cbfb = { 98 94 [2] bc 9a [2] 97 b6 [2] b9 94 [2] ad 8f [2] a2 95 [2] bc 88 [2] be 89 [2] a5 8f [2] b9 88 [2] a5 a7 }

  condition:
    any of them
}