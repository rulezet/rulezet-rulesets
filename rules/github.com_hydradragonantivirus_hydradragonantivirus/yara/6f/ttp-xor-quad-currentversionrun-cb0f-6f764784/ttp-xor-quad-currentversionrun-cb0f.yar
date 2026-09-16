rule TTP_XOR_QUAD_CurrentVersionRun_cb0f {
  strings:
    $key_cb0f = { 98 60 [2] bc 6e [2] 97 42 [2] b9 60 [2] ad 7b [2] a2 61 [2] bc 7c [2] be 7d [2] a5 7b [2] b9 7c [2] a5 53 }

  condition:
    any of them
}