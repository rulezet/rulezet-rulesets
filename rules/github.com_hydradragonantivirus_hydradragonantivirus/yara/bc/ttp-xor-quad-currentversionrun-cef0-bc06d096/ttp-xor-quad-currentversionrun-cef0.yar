rule TTP_XOR_QUAD_CurrentVersionRun_cef0 {
  strings:
    $key_cef0 = { 9d 9f [2] b9 91 [2] 92 bd [2] bc 9f [2] a8 84 [2] a7 9e [2] b9 83 [2] bb 82 [2] a0 84 [2] bc 83 [2] a0 ac }

  condition:
    any of them
}