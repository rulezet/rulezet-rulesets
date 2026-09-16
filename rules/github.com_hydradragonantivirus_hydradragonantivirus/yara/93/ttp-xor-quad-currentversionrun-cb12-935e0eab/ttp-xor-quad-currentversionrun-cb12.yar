rule TTP_XOR_QUAD_CurrentVersionRun_cb12 {
  strings:
    $key_cb12 = { 98 7d [2] bc 73 [2] 97 5f [2] b9 7d [2] ad 66 [2] a2 7c [2] bc 61 [2] be 60 [2] a5 66 [2] b9 61 [2] a5 4e }

  condition:
    any of them
}