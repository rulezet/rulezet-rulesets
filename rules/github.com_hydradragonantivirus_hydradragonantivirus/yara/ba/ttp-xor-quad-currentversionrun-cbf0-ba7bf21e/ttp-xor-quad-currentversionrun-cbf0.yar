rule TTP_XOR_QUAD_CurrentVersionRun_cbf0 {
  strings:
    $key_cbf0 = { 98 9f [2] bc 91 [2] 97 bd [2] b9 9f [2] ad 84 [2] a2 9e [2] bc 83 [2] be 82 [2] a5 84 [2] b9 83 [2] a5 ac }

  condition:
    any of them
}