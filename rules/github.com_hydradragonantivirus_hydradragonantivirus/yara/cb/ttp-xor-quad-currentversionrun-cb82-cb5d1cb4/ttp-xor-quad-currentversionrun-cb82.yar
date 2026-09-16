rule TTP_XOR_QUAD_CurrentVersionRun_cb82 {
  strings:
    $key_cb82 = { 98 ed [2] bc e3 [2] 97 cf [2] b9 ed [2] ad f6 [2] a2 ec [2] bc f1 [2] be f0 [2] a5 f6 [2] b9 f1 [2] a5 de }

  condition:
    any of them
}