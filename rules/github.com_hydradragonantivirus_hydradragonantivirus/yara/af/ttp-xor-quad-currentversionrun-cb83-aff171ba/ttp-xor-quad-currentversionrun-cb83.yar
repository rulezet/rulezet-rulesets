rule TTP_XOR_QUAD_CurrentVersionRun_cb83 {
  strings:
    $key_cb83 = { 98 ec [2] bc e2 [2] 97 ce [2] b9 ec [2] ad f7 [2] a2 ed [2] bc f0 [2] be f1 [2] a5 f7 [2] b9 f0 [2] a5 df }

  condition:
    any of them
}