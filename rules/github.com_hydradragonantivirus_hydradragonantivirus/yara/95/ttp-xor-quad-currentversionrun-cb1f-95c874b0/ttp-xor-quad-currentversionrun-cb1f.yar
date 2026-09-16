rule TTP_XOR_QUAD_CurrentVersionRun_cb1f {
  strings:
    $key_cb1f = { 98 70 [2] bc 7e [2] 97 52 [2] b9 70 [2] ad 6b [2] a2 71 [2] bc 6c [2] be 6d [2] a5 6b [2] b9 6c [2] a5 43 }

  condition:
    any of them
}