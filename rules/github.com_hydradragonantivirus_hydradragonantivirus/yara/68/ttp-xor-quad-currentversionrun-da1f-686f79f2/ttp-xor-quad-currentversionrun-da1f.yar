rule TTP_XOR_QUAD_CurrentVersionRun_da1f {
  strings:
    $key_da1f = { 89 70 [2] ad 7e [2] 86 52 [2] a8 70 [2] bc 6b [2] b3 71 [2] ad 6c [2] af 6d [2] b4 6b [2] a8 6c [2] b4 43 }

  condition:
    any of them
}